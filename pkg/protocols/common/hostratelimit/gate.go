package hostratelimit

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/projectdiscovery/ratelimit"

	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

var (
	// ErrGateClosed is returned by Acquire after the Gate was closed.
	ErrGateClosed = errors.New("hostratelimit: gate closed")
	// ErrInvalidRateLimit is returned by NewGate when the configured rate
	// limit or its duration is negative.
	ErrInvalidRateLimit = errors.New("hostratelimit: invalid rate limit")
)

// GateStats reports cumulative admission counters. Counters only increase
// over the gate's lifetime, and reading them after Close still returns the
// last values.
type GateStats struct {
	// GlobalWaits counts successful admissions through the global limiter.
	GlobalWaits uint64
	// HostWaits counts successful admissions through per-host limiters.
	HostWaits uint64
	// Rejected counts admissions that failed for reasons other than context
	// cancellation, such as an uninitialized per-host pool.
	Rejected uint64
	// Canceled counts admissions aborted by context cancellation or deadline.
	Canceled uint64
}

// Gate is the unified admission point for request rate limiting. It routes
// each request to the per-host limiter pool when per-host rate limiting is
// enabled and the host is known, and to the shared global limiter otherwise.
//
// Gate is safe for concurrent use. It does not own the per-host pool or the
// global limiter: Close only flips the gate's own state, is idempotent, and
// never disturbs requests that were already admitted.
type Gate struct {
	options   *types.Options
	global    *ratelimit.Limiter
	unlimited bool

	closed      atomic.Bool
	globalWaits atomic.Uint64
	hostWaits   atomic.Uint64
	rejected    atomic.Uint64
	canceled    atomic.Uint64
}

// NewGate creates a Gate routing between the per-host pool derived from
// options and the shared global limiter. A negative RateLimit or
// RateLimitDuration returns an error wrapping ErrInvalidRateLimit; a zero of
// either means unlimited and Acquire returns immediately without counting
// waits.
func NewGate(options *types.Options, global *ratelimit.Limiter) (*Gate, error) {
	if options != nil {
		if options.RateLimit < 0 {
			return nil, fmt.Errorf("%w: rate limit must not be negative: %d", ErrInvalidRateLimit, options.RateLimit)
		}
		if options.RateLimitDuration < 0 {
			return nil, fmt.Errorf("%w: rate limit duration must not be negative: %s", ErrInvalidRateLimit, options.RateLimitDuration)
		}
	}

	gate := &Gate{options: options, global: global}
	if options != nil && (options.RateLimit == 0 || options.RateLimitDuration == 0) {
		gate.unlimited = true
	}

	return gate, nil
}

// Acquire blocks until one request to host is admitted or ctx is canceled.
//
// A nil or already-canceled ctx is rejected before any token is consumed. A
// nil gate admits immediately. Errors from the per-host pool (such as
// dialers not initialized) are propagated as-is; the global path is only
// taken when per-host rate limiting is disabled or host is empty.
func (g *Gate) Acquire(ctx context.Context, host string) error {
	if g == nil {
		return nil
	}
	if g.closed.Load() {
		return ErrGateClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		g.canceled.Add(1)
		return context.Cause(ctx)
	}
	if g.unlimited {
		return nil
	}

	if g.options != nil && g.options.PerHostRateLimit && host != "" {
		limiter, err := GetPerHostRateLimiter(g.options, host)
		if err != nil {
			g.rejected.Add(1)
			return err
		}
		if limiter != nil {
			if err := limiter.Wait(ctx); err != nil {
				g.countWaitError(ctx)
				return err
			}
			g.hostWaits.Add(1)
			RecordPerHostRateLimitRequest(g.options, host)
			return nil
		}
	}

	if g.global != nil {
		if err := g.global.TakeContext(ctx); err != nil {
			g.countWaitError(ctx)
			return err
		}
		g.globalWaits.Add(1)
	}

	return nil
}

// countWaitError attributes a failed wait to cancellation or rejection.
func (g *Gate) countWaitError(ctx context.Context) {
	if ctx.Err() != nil {
		g.canceled.Add(1)
		return
	}
	g.rejected.Add(1)
}

// Stats returns the current cumulative counters. It is safe to call at any
// time, including after Close.
func (g *Gate) Stats() GateStats {
	if g == nil {
		return GateStats{}
	}
	return GateStats{
		GlobalWaits: g.globalWaits.Load(),
		HostWaits:   g.hostWaits.Load(),
		Rejected:    g.rejected.Load(),
		Canceled:    g.canceled.Load(),
	}
}

// Close marks the gate closed so later Acquire calls return ErrGateClosed.
// It is idempotent, always returns nil, and does not affect requests that
// were already admitted.
func (g *Gate) Close() error {
	if g == nil {
		return nil
	}
	g.closed.Store(true)
	return nil
}
