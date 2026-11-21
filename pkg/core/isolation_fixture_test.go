package core

import (
	"context"
	"errors"
	"os"
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

// The fixture is the acceptance shape of the isolation work: three units that
// must be isolated (crash, hang, leak) alongside normal units, and a target set
// on which every normal unit must still run.

// fixtureExecuter switches on the template ID it serves, mirroring how the
// fixture templates below differ only by ID.
type fixtureExecuter struct {
	id string

	mu      sync.Mutex
	runs    int
	onRun   func(ctx *scan.ScanContext)
	release chan struct{}
}

func (f *fixtureExecuter) Compile() error { return nil }
func (f *fixtureExecuter) Requests() int  { return 1 }
func (f *fixtureExecuter) Execute(ctx *scan.ScanContext) (bool, error) {
	f.mu.Lock()
	f.runs++
	f.mu.Unlock()
	if f.onRun != nil {
		f.onRun(ctx)
	}
	switch f.id {
	case "fixture-crash":
		panic("fixture crash: nil map write")
	case "fixture-hang":
		select {
		case <-f.release:
			return false, nil
		case <-ctx.Context().Done():
			return false, ctx.Context().Err()
		}
	case "fixture-leak":
		_, _ = isolation.TrackResource(ctx.Context(), "fixture page", func() error { return nil })
		return false, nil
	default:
		return true, nil
	}
}
func (f *fixtureExecuter) ExecuteWithResults(ctx *scan.ScanContext) ([]*output.ResultEvent, error) {
	matched, err := f.Execute(ctx)
	if err != nil || !matched {
		return nil, err
	}
	return []*output.ResultEvent{{TemplateID: f.id, Host: ctx.Input.MetaInput.Input, MatcherStatus: true}}, nil
}

func newFixtureEngine(templatesList []*templates.Template) (*Engine, *fixtureOutput) {
	out := &fixtureOutput{}
	options := &types.Options{
		BulkSize:                3,
		TemplateThreads:         3,
		HeadlessBulkSize:        1,
		HeadlessTemplateThreads: 1,
		Logger:                  gologger.DefaultLogger,
		IsolationOptions:        isolationtypes.DefaultOptions(),
	}
	// one attempt then isolate, so the fixture stays fast
	options.IsolationOptions.Retry = 0
	options.IsolationOptions.UnitTimeout = 100 * time.Millisecond
	engine := New(options)
	engine.SetExecuterOptions(&protocols.ExecutorOptions{
		Logger:       engine.Logger,
		Options:      options,
		ResumeCfg:    types.NewResumeCfg(),
		ProtocolType: tmpltypes.HTTPProtocol,
	})
	engine.Callback = out.write
	return engine, out
}

type fixtureOutput struct {
	mu   sync.Mutex
	seen []string
}

func (o *fixtureOutput) write(event *output.ResultEvent) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.seen = append(o.seen, event.TemplateID+"@"+event.Host)
}

func (o *fixtureOutput) findings() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.seen...)
}

func fixtureTemplates(hang chan struct{}) []*templates.Template {
	return []*templates.Template{
		{ID: "fixture-ok-1", Executer: &fixtureExecuter{id: "fixture-ok-1"}},
		{ID: "fixture-crash", Executer: &fixtureExecuter{id: "fixture-crash"}},
		{ID: "fixture-ok-2", Executer: &fixtureExecuter{id: "fixture-ok-2"}},
		{ID: "fixture-hang", Executer: &fixtureExecuter{id: "fixture-hang", release: hang}},
		{ID: "fixture-leak", Executer: &fixtureExecuter{id: "fixture-leak"}},
		{ID: "fixture-ok-3", Executer: &fixtureExecuter{id: "fixture-ok-3"}},
	}
}

func TestFixtureIsolatesCrashHangLeakAndRunsTheRest(t *testing.T) {
	targets := []string{"https://a.test", "https://b.test", "https://c.test"}
	hang := make(chan struct{})
	defer close(hang)

	engine, out := newFixtureEngine(nil)
	engine.ExecuteScanWithOpts(context.Background(), fixtureTemplates(hang), targetsOf(targets...), true)

	// every normal unit ran on every target and wrote its finding
	findings := out.findings()
	require.NotEmpty(t, findings)
	for _, target := range targets {
		for _, id := range []string{"fixture-ok-1", "fixture-ok-2", "fixture-ok-3"} {
			require.Contains(t, findings, id+"@"+target, "normal unit %s must run on %s", id, target)
		}
	}
	for _, finding := range findings {
		require.NotContains(t, finding, "fixture-crash")
		require.NotContains(t, finding, "fixture-hang")
		require.NotContains(t, finding, "fixture-leak")
	}
	require.Len(t, findings, 9, "each normal unit wrote one finding per target")

	// the isolation list names exactly the three fault classes
	summary := isolation.NewSummary(engine.IsolationRecorder(), time.Time{}, time.Time{})
	byTemplate := map[string]isolation.UnitSummary{}
	for _, unit := range summary.Units {
		byTemplate[unit.Template] = unit
	}
	require.Equal(t, isolation.ReasonPanic, byTemplate["fixture-crash"].Reason)
	require.Equal(t, isolation.ReasonTimeout, byTemplate["fixture-hang"].Reason)
	require.Equal(t, isolation.ReasonLeak, byTemplate["fixture-leak"].Reason)
	for _, id := range []string{"fixture-crash", "fixture-hang", "fixture-leak"} {
		require.True(t, byTemplate[id].Isolated, "%s must be isolated", id)
		require.Len(t, byTemplate[id].Targets, len(targets), "%s must name every affected target", id)
	}
	for _, id := range []string{"fixture-ok-1", "fixture-ok-2", "fixture-ok-3"} {
		require.NotContains(t, byTemplate, id, "a normal unit must not be isolated")
	}
}

func TestFixtureIsolatedUnitsStayOutOfFindings(t *testing.T) {
	// an isolated unit's late results must not appear in the findings list, and
	// the total must not grow because of the isolation bookkeeping
	engine, out := newFixtureEngine(nil)
	engine.ExecuteScanWithOpts(context.Background(), fixtureTemplates(make(chan struct{})), targetsOf("https://a.test"), true)
	findings := out.findings()
	require.ElementsMatch(t, []string{"fixture-ok-1@https://a.test", "fixture-ok-2@https://a.test", "fixture-ok-3@https://a.test"}, findings)
}

func TestFixtureIsolationDecisionsAreAuditable(t *testing.T) {
	engine, _ := newFixtureEngine(nil)
	engine.ExecuteScanWithOpts(context.Background(), fixtureTemplates(make(chan struct{})), targetsOf("https://a.test", "https://b.test"), true)

	recorder := engine.IsolationRecorder()
	decisions := recorder.Decisions()
	require.NotEmpty(t, decisions)
	for _, decision := range decisions {
		require.NotEmpty(t, decision.Template)
		require.NotEmpty(t, decision.Reason)
		require.NotEmpty(t, decision.Outcome)
		require.NotEmpty(t, decision.Err)
		require.Equal(t, 1, decision.Attempt, "isolation happens on the last attempt")
	}
	// the decisions are looked up by unit
	for _, unit := range recorder.IsolatedUnits() {
		found := false
		for _, decision := range decisions {
			if decision.Unit == unit.Unit {
				found = true
				break
			}
		}
		require.True(t, found, "unit %s has no decision to look up", unit.Unit)
	}
}

// TestFixtureDoesNotLeakResources checks the resource set closes what a fault
// left open, by counting closers that ran.
func TestFixtureDoesNotLeakResources(t *testing.T) {
	var opened, closed atomic.Int32
	exec := &fixtureExecuter{id: "fixture-leak"}
	exec.onRun = func(ctx *scan.ScanContext) {
		opened.Add(1)
		_, _ = isolation.TrackResource(ctx.Context(), "counted page", func() error {
			closed.Add(1)
			return nil
		})
	}
	leakTemplate := &templates.Template{ID: "fixture-leak", Executer: exec}

	options := &types.Options{BulkSize: 1, TemplateThreads: 1, HeadlessBulkSize: 1, HeadlessTemplateThreads: 1, Logger: gologger.DefaultLogger, IsolationOptions: isolationtypes.DefaultOptions()}
	options.IsolationOptions.Retry = 0
	engine := New(options)
	engine.SetExecuterOptions(&protocols.ExecutorOptions{Logger: engine.Logger, Options: options, ResumeCfg: types.NewResumeCfg(), ProtocolType: tmpltypes.HTTPProtocol})
	engine.ExecuteScanWithOpts(context.Background(), []*templates.Template{leakTemplate}, targetsOf("a", "b", "c"), true)

	require.EqualValues(t, 3, opened.Load())
	require.EqualValues(t, 3, closed.Load(), "every opened page is reclaimed even though the unit leaked them")
}

func TestFixtureCleanupFailureIsRecordedAndBatchContinues(t *testing.T) {
	var runs atomic.Int32
	exec := &fixtureExecuter{id: "fixture-ok-1"}
	exec.onRun = func(ctx *scan.ScanContext) {
		runs.Add(1)
		_, _ = isolation.TrackResource(ctx.Context(), "stuck", func() error {
			return errors.New("cannot close")
		})
	}
	engine := New(&types.Options{BulkSize: 1, TemplateThreads: 1, HeadlessBulkSize: 1, HeadlessTemplateThreads: 1, Logger: gologger.DefaultLogger, IsolationOptions: isolationtypes.DefaultOptions()})
	engine.options.IsolationOptions.Retry = 0
	engine.SetExecuterOptions(&protocols.ExecutorOptions{Logger: engine.Logger, Options: engine.options, ResumeCfg: types.NewResumeCfg(), ProtocolType: tmpltypes.HTTPProtocol})

	engine.ExecuteScanWithOpts(context.Background(), []*templates.Template{{ID: "fixture-ok-1", Executer: exec}}, targetsOf("a", "b"), true)

	require.EqualValues(t, 2, runs.Load(), "a failed reclaim does not stop the batch")
	summary := isolation.NewSummary(engine.IsolationRecorder(), time.Time{}, time.Time{})
	require.Len(t, summary.Units, 1)
	require.Equal(t, 2, summary.Units[0].Failures)
}

// TestFixtureConcurrencyIsNotReduced compares the peak in-flight units with
// and without a crashing template.
func TestFixtureConcurrencyIsNotReduced(t *testing.T) {
	peak := func(withCrash bool) int32 {
		var inFlight, maxInFlight atomic.Int32
		ok := &concurrencyExecuter{inFlight: &inFlight, max: &maxInFlight}
		list := []*templates.Template{
			{ID: "ok-1", Executer: ok},
			{ID: "ok-2", Executer: ok},
			{ID: "ok-3", Executer: ok},
			{ID: "ok-4", Executer: ok},
		}
		if withCrash {
			list = append(list, &templates.Template{ID: "crashy", Executer: &panicExecuter{}})
		}
		options := &types.Options{BulkSize: 4, TemplateThreads: 4, HeadlessBulkSize: 1, HeadlessTemplateThreads: 1, Logger: gologger.DefaultLogger, IsolationOptions: isolationtypes.DefaultOptions()}
		options.IsolationOptions.Retry = 0
		engine := New(options)
		engine.SetExecuterOptions(&protocols.ExecutorOptions{Logger: engine.Logger, Options: options, ResumeCfg: types.NewResumeCfg(), ProtocolType: tmpltypes.HTTPProtocol})
		engine.ExecuteScanWithOpts(context.Background(), list, targetsOf("a"), true)
		return maxInFlight.Load()
	}
	withoutCrash := peak(false)
	withCrash := peak(true)
	require.Greater(t, withCrash, int32(1))
	require.GreaterOrEqual(t, withCrash, withoutCrash-1, "isolation must not squash concurrency")
}

type concurrencyExecuter struct {
	inFlight *atomic.Int32
	max      *atomic.Int32
}

func (c *concurrencyExecuter) Compile() error { return nil }
func (c *concurrencyExecuter) Requests() int  { return 1 }
func (c *concurrencyExecuter) Execute(*scan.ScanContext) (bool, error) {
	current := c.inFlight.Add(1)
	defer c.inFlight.Add(-1)
	for {
		maximum := c.max.Load()
		if current <= maximum || c.max.CompareAndSwap(maximum, current) {
			break
		}
	}
	time.Sleep(20 * time.Millisecond)
	return true, nil
}
func (c *concurrencyExecuter) ExecuteWithResults(*scan.ScanContext) ([]*output.ResultEvent, error) {
	return nil, nil
}

func TestFixtureWorkflowChildCrashDoesNotEndTheProcess(t *testing.T) {
	engine := newIsolationTestEngine(0)

	// a workflow child crashes on its own goroutine, where the parent unit's
	// recover cannot see it
	crashed := make(chan struct{})
	go func() {
		defer close(crashed)
		defer engine.recoverWorkflowStep("child.yaml")
		panic("workflow child boom")
	}()
	<-crashed

	decisions := engine.IsolationRecorder().Decisions()
	require.Len(t, decisions, 1)
	require.Equal(t, "child.yaml", decisions[0].Template)
	require.Equal(t, isolation.ReasonPanic, decisions[0].Reason)
	require.Contains(t, decisions[0].Err, "workflow child boom")
}

// TestFixtureDecisionForwardedToCallback checks an embedding application can
// audit decisions live through the template execution callback.
func TestFixtureDecisionForwardedToCallback(t *testing.T) {
	engine := newIsolationTestEngine(0)
	var events []TemplateExecutionEvent
	var mu sync.Mutex
	engine.SetTemplateExecutionCallback(func(event TemplateExecutionEvent) {
		if event.Isolation == nil {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		events = append(events, event)
	})
	_, err := engine.runUnit(context.Background(), &templates.Template{ID: "crashy", Executer: &panicExecuter{}}, &contextargs.MetaInput{Input: "a"})
	require.Error(t, err)
	require.Len(t, events, 1)
	require.Equal(t, "crashy", events[0].TemplateID)
	require.Equal(t, isolation.ReasonPanic, events[0].Isolation.Reason)
}

// TestFixtureNoResidualTempFiles checks that a unit isolated after leaving a
// temporary file behind has it reclaimed and recorded.
func TestFixtureNoResidualTempFiles(t *testing.T) {
	dir := t.TempDir()
	var trackedName string
	exec := &fixtureExecuter{id: "fixture-leak"}
	exec.onRun = func(ctx *scan.ScanContext) {
		file, err := os.CreateTemp(dir, "fixture-*")
		if err != nil {
			return
		}
		trackedName = file.Name()
		_, _ = isolation.TrackResource(ctx.Context(), "fixture temp handle", file.Close)
		_, _ = isolation.TrackResource(ctx.Context(), "fixture temp file", func() error {
			return os.Remove(trackedName)
		})
	}
	engine := newIsolationTestEngine(0)
	_, err := engine.runUnit(context.Background(), &templates.Template{ID: "fixture-leak", Executer: exec}, &contextargs.MetaInput{Input: "a"})
	require.Error(t, err, "a unit that leaves resources open is isolated")

	_, statErr := os.Stat(trackedName)
	require.True(t, os.IsNotExist(statErr), "the temporary file was reclaimed")

	leaks := 0
	for _, decision := range engine.IsolationRecorder().Decisions() {
		if decision.Reason == isolation.ReasonLeak {
			leaks++
		}
	}
	require.Equal(t, 1, leaks, "the unit's leftover file is recorded as a leak")
}
