package core

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/isolation"
	isolationtypes "github.com/projectdiscovery/nuclei/v3/pkg/isolation/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/scan"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	tmpltypes "github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

// panicExecuter crashes on every execution.
type panicExecuter struct{ calls atomic.Int32 }

func (p *panicExecuter) Compile() error { return nil }
func (p *panicExecuter) Requests() int  { return 1 }
func (p *panicExecuter) Execute(*scan.ScanContext) (bool, error) {
	p.calls.Add(1)
	panic("boom")
}
func (p *panicExecuter) ExecuteWithResults(*scan.ScanContext) ([]*output.ResultEvent, error) {
	p.calls.Add(1)
	panic("boom")
}

// hangExecuter blocks until its context ends, and honours nothing else.
type hangExecuter struct {
	calls   atomic.Int32
	release chan struct{}
}

func (h *hangExecuter) Compile() error { return nil }
func (h *hangExecuter) Requests() int  { return 1 }
func (h *hangExecuter) Execute(ctx *scan.ScanContext) (bool, error) {
	h.calls.Add(1)
	select {
	case <-h.release:
		return false, nil
	case <-ctx.Context().Done():
		return false, ctx.Context().Err()
	}
}
func (h *hangExecuter) ExecuteWithResults(ctx *scan.ScanContext) ([]*output.ResultEvent, error) {
	_, err := h.Execute(ctx)
	return nil, err
}

// leakExecuter opens a resource and never closes it.
type leakExecuter struct{ opened atomic.Int32 }

func (l *leakExecuter) Compile() error { return nil }
func (l *leakExecuter) Requests() int  { return 1 }
func (l *leakExecuter) Execute(ctx *scan.ScanContext) (bool, error) {
	_, _ = isolation.TrackResource(ctx.Context(), "fake page", func() error {
		return nil
	})
	l.opened.Add(1)
	return false, nil
}

func (l *leakExecuter) ExecuteWithResults(ctx *scan.ScanContext) ([]*output.ResultEvent, error) {
	_, err := l.Execute(ctx)
	return nil, err
}

// closeFailExecuter opens a resource whose closer fails.
type closeFailExecuter struct{}

func (c *closeFailExecuter) Compile() error { return nil }
func (c *closeFailExecuter) Requests() int  { return 1 }
func (c *closeFailExecuter) Execute(ctx *scan.ScanContext) (bool, error) {
	_, _ = isolation.TrackResource(ctx.Context(), "stuck connection", func() error {
		return errors.New("close refused")
	})
	return false, nil
}
func (c *closeFailExecuter) ExecuteWithResults(ctx *scan.ScanContext) ([]*output.ResultEvent, error) {
	_, err := c.Execute(ctx)
	return nil, err
}

func newIsolationTestEngine(retry int) *Engine {
	options := &types.Options{
		BulkSize:                2,
		TemplateThreads:         2,
		HeadlessBulkSize:        1,
		HeadlessTemplateThreads: 1,
		Logger:                  gologger.DefaultLogger,
		IsolationOptions:        isolationtypes.DefaultOptions(),
	}
	options.IsolationOptions.Retry = retry
	engine := New(options)
	engine.SetExecuterOptions(&protocols.ExecutorOptions{
		Logger:       engine.Logger,
		Options:      options,
		ResumeCfg:    types.NewResumeCfg(),
		ProtocolType: tmpltypes.HTTPProtocol,
	})
	return engine
}

func TestRunUnitRecoversFromPanicAndIsolatesAfterRetries(t *testing.T) {
	engine := newIsolationTestEngine(1)
	template := &templates.Template{ID: "crashy", Executer: &panicExecuter{}}
	value := &contextargs.MetaInput{Input: "target-a"}

	_, err := engine.runUnit(context.Background(), template, value)
	require.ErrorIs(t, err, isolation.ErrUnitFault)
	require.ErrorIs(t, err, errUnitPanic)

	decisions := engine.IsolationRecorder().Decisions()
	require.Len(t, decisions, 2, "one recovered attempt and one isolation")
	require.Equal(t, isolation.Recovered, decisions[0].Outcome)
	require.Equal(t, isolation.Isolated, decisions[1].Outcome)
	require.Equal(t, isolation.ReasonPanic, decisions[1].Reason)
	require.Equal(t, "target-a", decisions[1].Target)

	// the pair is isolated, so another run on the same target is skipped
	_, err = engine.runUnit(context.Background(), template, value)
	require.ErrorIs(t, err, errUnitSkipped)
}

func TestRunUnitRetryIsBounded(t *testing.T) {
	exec := &panicExecuter{}
	engine := newIsolationTestEngine(0)
	template := &templates.Template{ID: "crashy", Executer: exec}

	_, err := engine.runUnit(context.Background(), template, &contextargs.MetaInput{Input: "a"})
	require.Error(t, err)
	require.EqualValues(t, 1, exec.calls.Load(), "no retries configured means one attempt")

	exec = &panicExecuter{}
	engine = newIsolationTestEngine(3)
	template = &templates.Template{ID: "crashy", Executer: exec}
	_, err = engine.runUnit(context.Background(), template, &contextargs.MetaInput{Input: "a"})
	require.Error(t, err)
	require.EqualValues(t, 4, exec.calls.Load(), "the retry cap bounds the attempts")
}

func TestRunUnitTimesOutAHangingUnit(t *testing.T) {
	hanging := &hangExecuter{release: make(chan struct{})}
	defer close(hanging.release)
	engine := newIsolationTestEngine(0)
	engine.options.IsolationOptions.UnitTimeout = 50 * time.Millisecond
	template := &templates.Template{ID: "hanging", Executer: hanging}

	started := time.Now()
	_, err := engine.runUnit(context.Background(), template, &contextargs.MetaInput{Input: "slow"})
	require.ErrorIs(t, err, errUnitTimeout)
	require.Less(t, time.Since(started), 2*time.Second, "a hang must not hold the slot")

	decisions := engine.IsolationRecorder().Decisions()
	require.Len(t, decisions, 1)
	require.Equal(t, isolation.ReasonTimeout, decisions[0].Reason)
}

func TestRunUnitClosesLeakedResourcesAndContinues(t *testing.T) {
	leaker := &leakExecuter{}
	engine := newIsolationTestEngine(0)
	template := &templates.Template{ID: "leaky", Executer: leaker}

	// the unit returned while holding a resource: it is isolated on its target
	_, err := engine.runUnit(context.Background(), template, &contextargs.MetaInput{Input: "a"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "left open")

	decisions := engine.IsolationRecorder().Decisions()
	require.Len(t, decisions, 1)
	require.Equal(t, isolation.ReasonLeak, decisions[0].Reason)
	require.Equal(t, isolation.Isolated, decisions[0].Outcome)
	require.Contains(t, decisions[0].Err, "left open")
}

func TestRunUnitRecordsCleanupFailureAndStillReturns(t *testing.T) {
	engine := newIsolationTestEngine(0)
	template := &templates.Template{ID: "stuck-close", Executer: &closeFailExecuter{}}

	// the unit returned normally; the failed reclaim is recorded for the audit
	// trail and isolates the pair, while the batch carries on to the next one
	_, err := engine.runUnit(context.Background(), template, &contextargs.MetaInput{Input: "a"})
	require.Error(t, err)
	decisions := engine.IsolationRecorder().Decisions()
	require.Len(t, decisions, 1)
	require.Equal(t, isolation.ReasonCleanup, decisions[0].Reason)
	require.Equal(t, isolation.Isolated, decisions[0].Outcome)
	require.Contains(t, decisions[0].Err, "close refused")

	// another pair still runs: one failed reclaim never stops the batch
	_, err = engine.runUnit(context.Background(), template, &contextargs.MetaInput{Input: "b"})
	require.Error(t, err)
	require.Len(t, engine.IsolationRecorder().Decisions(), 2)
}

// resultsExecuterForTest reports one match for a host through
// ExecuteWithResults, the path the engine takes when a callback is installed.
type resultsExecuterForTest struct{ host string }

func (r *resultsExecuterForTest) Compile() error { return nil }
func (r *resultsExecuterForTest) Requests() int  { return 1 }
func (r *resultsExecuterForTest) Execute(*scan.ScanContext) (bool, error) {
	return true, nil
}
func (r *resultsExecuterForTest) ExecuteWithResults(*scan.ScanContext) ([]*output.ResultEvent, error) {
	return []*output.ResultEvent{{Host: r.host, MatcherStatus: true}}, nil
}

func TestQuarantineStopsTemplateOnRemainingTargets(t *testing.T) {
	engine := newIsolationTestEngine(0)
	engine.SetIsolationRecorder(isolation.NewRecorder(isolation.Threshold{Retry: 0, SignatureFailures: 2}))
	exec := &panicExecuter{}
	template := &templates.Template{ID: "crashy", Executer: exec}

	_, err := engine.runUnit(context.Background(), template, &contextargs.MetaInput{Input: "a"})
	require.Error(t, err)
	_, err = engine.runUnit(context.Background(), template, &contextargs.MetaInput{Input: "b"})
	require.Error(t, err)

	// the template failed on two distinct targets: later targets are skipped
	calls := exec.calls.Load()
	_, err = engine.runUnit(context.Background(), template, &contextargs.MetaInput{Input: "c"})
	require.ErrorIs(t, err, errUnitSkipped)
	require.Equal(t, calls, exec.calls.Load(), "the isolated template did not run")

	recorder := engine.IsolationRecorder()
	// the two isolated targets plus the one target the quarantine turned away
	require.Equal(t, 3, recorder.Affected("crashy"))
	summary := isolation.NewSummary(recorder, time.Now(), time.Now())
	require.Equal(t, 3, summary.Isolated[0].Affected)
}

func TestRunUnitKeepsNormalResultsAndOrder(t *testing.T) {
	var (
		mu   sync.Mutex
		seen []string
	)
	options := &types.Options{BulkSize: 2, TemplateThreads: 2, HeadlessBulkSize: 1, HeadlessTemplateThreads: 1, Logger: gologger.DefaultLogger}
	engine := New(options)
	engine.SetExecuterOptions(&protocols.ExecutorOptions{
		Logger:       engine.Logger,
		Options:      options,
		ResumeCfg:    types.NewResumeCfg(),
		ProtocolType: tmpltypes.HTTPProtocol,
	})
	engine.Callback = func(event *output.ResultEvent) {
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, event.Host)
	}

	// one crasher among two normal templates: every normal result is written
	// once, and the crasher adds none
	templatesList := []*templates.Template{
		{ID: "first", Executer: &resultsExecuterForTest{host: "a"}},
		{ID: "crashy", Executer: &panicExecuter{}},
		{ID: "second", Executer: &resultsExecuterForTest{host: "a"}},
	}
	engine.ExecuteScanWithOpts(context.Background(), templatesList, targetsOf("a"), true)

	require.Equal(t, []string{"a", "a"}, seen)
	summary := isolation.NewSummary(engine.IsolationRecorder(), time.Now(), time.Now())
	require.Len(t, summary.Isolated, 1)
	require.Equal(t, "crashy", summary.Isolated[0].Unit)
}

func TestRunUnitCountsOneTaskRegardlessOfRetries(t *testing.T) {
	// an isolated pair is one task; retries and the skip path must not inflate
	// the done count, or the progress total no longer matches the schedule
	engine := newIsolationTestEngine(2)
	recorder := &taskRecorder{}
	engine.executerOpts.Progress = recorder
	exec := &panicExecuter{}
	template := &templates.Template{ID: "crashy", Executer: exec}

	_, err := engine.runUnit(context.Background(), template, &contextargs.MetaInput{Input: "a"})
	require.Error(t, err)
	require.EqualValues(t, 3, exec.calls.Load(), "the retry cap bounds the attempts")

	// a skipped pair is a done task too
	_, err = engine.runUnit(context.Background(), template, &contextargs.MetaInput{Input: "a"})
	require.ErrorIs(t, err, errUnitSkipped)
	require.EqualValues(t, 2, recorder.done.Load(), "one task per pair, not per attempt")
}

func TestIsolationDoesNotReduceConcurrency(t *testing.T) {
	const templateCount = 6
	var inFlight, maxInFlight atomic.Int32
	exec := &countingConcurrencyExecuter{inFlight: &inFlight, maxInFlight: &maxInFlight}

	options := &types.Options{
		BulkSize:                1,
		TemplateThreads:         templateCount,
		HeadlessBulkSize:        1,
		HeadlessTemplateThreads: 1,
		Logger:                  gologger.DefaultLogger,
	}
	engine := New(options)
	if options.IsolationOptions == nil {
		options.IsolationOptions = isolationtypes.DefaultOptions()
		options.IsolationOptions.Retry = 0
	}
	engine.SetExecuterOptions(&protocols.ExecutorOptions{
		Logger:       engine.Logger,
		Options:      options,
		ResumeCfg:    types.NewResumeCfg(),
		ProtocolType: tmpltypes.HTTPProtocol,
	})
	templatesList := make([]*templates.Template, 0, templateCount)
	for i := 0; i < templateCount; i++ {
		templatesList = append(templatesList, &templates.Template{ID: fmt.Sprintf("t-%d", i), Executer: exec})
	}
	engine.ExecuteScanWithOpts(context.Background(), templatesList, targetsOf("a"), true)

	require.Greater(t, maxInFlight.Load(), int32(1), "units still run concurrently")
}

type countingConcurrencyExecuter struct {
	inFlight    *atomic.Int32
	maxInFlight *atomic.Int32
}

func (c *countingConcurrencyExecuter) Compile() error { return nil }
func (c *countingConcurrencyExecuter) Requests() int  { return 1 }
func (c *countingConcurrencyExecuter) Execute(*scan.ScanContext) (bool, error) {
	current := c.inFlight.Add(1)
	defer c.inFlight.Add(-1)
	for {
		maximum := c.maxInFlight.Load()
		if current <= maximum || c.maxInFlight.CompareAndSwap(maximum, current) {
			break
		}
	}
	time.Sleep(10 * time.Millisecond)
	return true, nil
}
func (c *countingConcurrencyExecuter) ExecuteWithResults(*scan.ScanContext) ([]*output.ResultEvent, error) {
	return nil, nil
}
