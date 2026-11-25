package hostratelimit

import (
	"context"
	"testing"
	"time"

	"github.com/projectdiscovery/ratelimit"
	"github.com/stretchr/testify/require"
	"github.com/tarunKoyalwar/goleak"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/variables"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

// newGateTestOptions returns per-host rate limit options bound to a fresh
// execution id with a clean protocol state.
func newGateTestOptions(t *testing.T, rateLimit int, duration time.Duration) *types.Options {
	t.Helper()

	options := types.DefaultOptions()
	options.SetExecutionID(t.Name())
	options.PerHostRateLimit = true
	options.RateLimit = rateLimit
	options.RateLimitDuration = duration

	// Reset any state a previous run of this test (-count>1) left behind so
	// every run starts with a fresh pool and full token buckets.
	protocolstate.Close(options.ExecutionId)
	require.NoError(t, protocolstate.Init(options))
	t.Cleanup(func() { protocolstate.Close(options.ExecutionId) })

	return options
}

func TestGatePerHostAdmissionTiming(t *testing.T) {
	options := newGateTestOptions(t, 2, time.Second)
	gate, err := NewGate(options, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, gate.Close()) })

	start := time.Now()
	for i := 0; i < 5; i++ {
		require.NoError(t, gate.Acquire(context.Background(), "https://gate-timing.example.com"))
	}
	elapsed := time.Since(start)
	require.GreaterOrEqual(t, elapsed, 1500*time.Millisecond, "five admissions at 2/s must take at least 1.5s")
	require.LessOrEqual(t, elapsed, 2500*time.Millisecond, "five admissions at 2/s must take at most 2.5s")

	stats := gate.Stats()
	require.Equal(t, uint64(5), stats.HostWaits)
	require.Zero(t, stats.GlobalWaits)
}

func TestGateSeparateHostsDoNotShareBudget(t *testing.T) {
	options := newGateTestOptions(t, 2, time.Second)
	gate, err := NewGate(options, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, gate.Close()) })

	start := time.Now()
	for _, host := range []string{"https://first-gate.example.com", "https://second-gate.example.com"} {
		for i := 0; i < 2; i++ {
			require.NoError(t, gate.Acquire(context.Background(), host))
		}
	}
	require.Less(t, time.Since(start), 200*time.Millisecond, "independent host budgets must admit immediately")
	require.Equal(t, uint64(4), gate.Stats().HostWaits)
}

func TestGateCancelThenReacquireWithinBudget(t *testing.T) {
	options := newGateTestOptions(t, 1, 100*time.Millisecond)
	gate, err := NewGate(options, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, gate.Close()) })

	require.NoError(t, gate.Acquire(context.Background(), "https://gate-cancel.example.com"))

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- gate.Acquire(ctx, "https://gate-cancel.example.com") }()
	time.Sleep(30 * time.Millisecond)
	cancel()
	require.ErrorIs(t, <-result, context.Canceled)

	start := time.Now()
	require.NoError(t, gate.Acquire(context.Background(), "https://gate-cancel.example.com"))
	require.Less(t, time.Since(start), 200*time.Millisecond, "a canceled reservation must return its token")

	stats := gate.Stats()
	require.Equal(t, uint64(2), stats.HostWaits)
	require.Equal(t, uint64(1), stats.Canceled)
}

func TestGateGlobalPathAndStatsAccounting(t *testing.T) {
	options := types.DefaultOptions()
	options.SetExecutionID(t.Name())
	options.PerHostRateLimit = true
	options.RateLimit = 100
	options.RateLimitDuration = time.Second
	protocolstate.Close(options.ExecutionId)
	require.NoError(t, protocolstate.Init(options))
	t.Cleanup(func() { protocolstate.Close(options.ExecutionId) })

	global := ratelimit.New(context.Background(), 100, time.Second)
	t.Cleanup(global.Stop)

	gate, err := NewGate(options, global)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, gate.Close()) })

	successes := 0
	for i := 0; i < 3; i++ {
		require.NoError(t, gate.Acquire(context.Background(), "https://gate-stats.example.com"))
		successes++
	}
	// Empty host falls back to the global limiter even in per-host mode.
	for i := 0; i < 2; i++ {
		require.NoError(t, gate.Acquire(context.Background(), ""))
		successes++
	}

	stats := gate.Stats()
	require.Equal(t, uint64(3), stats.HostWaits)
	require.Equal(t, uint64(2), stats.GlobalWaits)
	require.Equal(t, uint64(successes), stats.GlobalWaits+stats.HostWaits,
		"global and host waits together must equal the number of admitted requests")
}

func TestGateUnlimitedConfigurations(t *testing.T) {
	tests := []struct {
		name      string
		rateLimit int
		duration  time.Duration
	}{
		{"zero rate limit", 0, time.Second},
		{"zero duration", 10, 0},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options := &types.Options{
				PerHostRateLimit:  true,
				RateLimit:         test.rateLimit,
				RateLimitDuration: test.duration,
			}
			gate, err := NewGate(options, nil)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, gate.Close()) })

			for i := 0; i < 50; i++ {
				require.NoError(t, gate.Acquire(context.Background(), "https://unlimited-gate.example.com"))
			}

			stats := gate.Stats()
			require.Zero(t, stats.HostWaits, "unlimited gates must not count host waits")
			require.Zero(t, stats.GlobalWaits)
		})
	}
}

func TestGateRejectsNegativeConfiguration(t *testing.T) {
	tests := []struct {
		name      string
		rateLimit int
		duration  time.Duration
	}{
		{"negative rate limit", -1, time.Second},
		{"negative duration", 1, -time.Second},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options := &types.Options{RateLimit: test.rateLimit, RateLimitDuration: test.duration}
			gate, err := NewGate(options, nil)
			require.ErrorIs(t, err, ErrInvalidRateLimit)
			require.Nil(t, gate)
		})
	}
}

func TestGatePropagatesUninitializedDialers(t *testing.T) {
	// No protocolstate.Init for this execution id: the per-host pool cannot
	// be created and the error must surface instead of silently admitting.
	options := types.DefaultOptions()
	options.SetExecutionID(t.Name())
	options.PerHostRateLimit = true
	options.RateLimit = 10
	options.RateLimitDuration = time.Second
	protocolstate.Close(options.ExecutionId)

	gate, err := NewGate(options, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, gate.Close()) })

	err = gate.Acquire(context.Background(), "https://no-dialers.example.com")
	require.Error(t, err, "an uninitialized per-host pool must not silently admit")
	require.Contains(t, err.Error(), "dialers not initialized")
	require.Equal(t, uint64(1), gate.Stats().Rejected)
	require.Zero(t, gate.Stats().HostWaits)
}

func TestGatePreCanceledContextConsumesNoToken(t *testing.T) {
	options := newGateTestOptions(t, 1, time.Hour)
	gate, err := NewGate(options, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, gate.Close()) })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = gate.Acquire(ctx, "https://pre-canceled.example.com")
	require.ErrorIs(t, err, context.Canceled)

	// The canceled acquire consumed no token, so the next one admits fast.
	start := time.Now()
	require.NoError(t, gate.Acquire(context.Background(), "https://pre-canceled.example.com"))
	require.Less(t, time.Since(start), 200*time.Millisecond)
	require.Equal(t, uint64(1), gate.Stats().HostWaits)
	require.Equal(t, uint64(1), gate.Stats().Canceled)
}

func TestGateCloseIsIdempotent(t *testing.T) {
	gate, err := NewGate(&types.Options{RateLimit: 10, RateLimitDuration: time.Second}, nil)
	require.NoError(t, err)

	require.NoError(t, gate.Close())
	require.NoError(t, gate.Close(), "repeated Close must return nil")

	err = gate.Acquire(context.Background(), "https://closed-gate.example.com")
	require.ErrorIs(t, err, ErrGateClosed)

	// Counters stay readable after Close.
	require.NotPanics(t, func() { _ = gate.Stats() })
}

func TestGateResolverAndProtocolstateCloseOrders(t *testing.T) {
	defer goleak.VerifyNone(t,
		goleak.IgnoreAnyContainingPkg("go.opencensus.io/stats/view"),
		goleak.IgnoreAnyContainingPkg("github.com/syndtr/goleveldb/leveldb"),
		// The per-host pool's expirable LRU runs a cleanup goroutine for the
		// pool's whole lifetime; it is pre-existing and has no close hook.
		goleak.IgnoreAnyContainingPkg("github.com/hashicorp/golang-lru/v2/expirable"),
	)

	newComponents := func(suffix string) (*types.Options, *variables.Resolver, *Gate) {
		options := types.DefaultOptions()
		options.SetExecutionID(t.Name() + suffix)
		options.PerHostRateLimit = true
		options.RateLimit = 10
		options.RateLimitDuration = time.Second
		protocolstate.Close(options.ExecutionId)
		require.NoError(t, protocolstate.Init(options))

		gate, err := NewGate(options, nil)
		require.NoError(t, err)
		require.NoError(t, gate.Acquire(context.Background(), "https://close-order.example.com"))

		resolver := variables.NewResolver(8)
		_, err = resolver.Resolve(context.Background(), variables.ResolveKey{TemplateID: "tpl"}, func(ctx context.Context) (variables.Snapshot, error) {
			return variables.NewScope().Snapshot(), nil
		})
		require.NoError(t, err)

		return options, resolver, gate
	}

	t.Run("resolver before protocolstate", func(t *testing.T) {
		options, resolver, gate := newComponents("-a")
		resolver.Close()
		protocolstate.Close(options.ExecutionId)
		require.NoError(t, gate.Close())
	})

	t.Run("protocolstate before resolver", func(t *testing.T) {
		options, resolver, gate := newComponents("-b")
		protocolstate.Close(options.ExecutionId)
		resolver.Close()
		require.NoError(t, gate.Close())
	})
}
