package core

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/isolation"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/scan"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	tmpltypes "github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
)

// errUnitPanic is wrapped by the error a crashed unit returns. Every unit
// fault wraps isolation.ErrUnitFault so host-level error tracking can count
// it.
var errUnitPanic = fmt.Errorf("%w: panicked", isolation.ErrUnitFault)

// errUnitTimeout is returned by a unit that exceeded its deadline.
var errUnitTimeout = fmt.Errorf("%w: timed out", isolation.ErrUnitFault)

// errUnitSkipped is returned when the unit no longer runs because it or its
// template was isolated. Callers treat it as a done task, never as a match.
var errUnitSkipped = errors.New("execution unit isolated earlier in the scan")

// isolationDefaultRetry mirrors the runner default for engines built without
// isolation options: a faulted unit is isolated on its first fault.
const isolationDefaultRetry = 0

// unitResult is what one isolated run of a template on a target produced.
type unitResult struct {
	matched bool
	err     error
	// reason is set when the run crashed, timed out or leaked; empty on a
	// normal return, including a normal error.
	reason isolation.Reason
	// detail is the panic value or timeout description recorded with the
	// decision.
	detail string
	// leaked is how many tracked resources the unit returned without closing.
	leaked int
	// leakDetail names the leak for the decision record.
	leakDetail string
	// cleanupErrs are resources that could not be reclaimed.
	cleanupErrs []error
}

// isolationRecorder returns the scan's recorder, creating the default one on
// first use. Isolation is always available so a crash in a unit cannot end the
// process even for an SDK or test that built the engine directly.
func (e *Engine) isolationRecorder() *isolation.Recorder {
	if e.recorder != nil {
		return e.recorder
	}
	e.isolationOnce.Do(func() {
		threshold := isolation.Threshold{Retry: isolationDefaultRetry}
		if e.options != nil && e.options.IsolationOptions != nil {
			threshold.Retry = e.options.IsolationOptions.RetryCount()
			threshold.SignatureFailures = e.options.IsolationOptions.SignatureThreshold()
		}
		e.recorder = isolation.NewRecorder(threshold)
	})
	return e.recorder
}

// SetIsolationRecorder installs a recorder configured by the runner.
func (e *Engine) SetIsolationRecorder(recorder *isolation.Recorder) {
	if recorder == nil {
		return
	}
	e.recorder = recorder
	e.isolationOnce.Do(func() {})
}

// IsolationRecorder exposes the recorder so the runner can report after the
// scan.
func (e *Engine) IsolationRecorder() *isolation.Recorder {
	return e.isolationRecorder()
}

// unitTimeout returns the deadline one template run gets. It derives from the
// template protocol and the request timeout, so a hang blocked on a read or on
// a remote response ends before it can hold an execution slot forever.
func (e *Engine) unitTimeout(template *templates.Template) time.Duration {
	if e.options != nil && e.options.IsolationOptions != nil && e.options.IsolationOptions.UnitTimeout > 0 {
		return e.options.IsolationOptions.UnitTimeout
	}
	requestTimeout := 10 * time.Second
	if e.options != nil {
		requestTimeout = e.options.GetTimeouts().HttpTimeout
	}
	var timeout time.Duration
	switch template.Type() {
	case tmpltypes.HeadlessProtocol:
		timeout = requestTimeout + 30*time.Second
	case tmpltypes.WorkflowProtocol:
		timeout = 4 * requestTimeout
	case tmpltypes.CodeProtocol, tmpltypes.JavascriptProtocol:
		timeout = 2 * requestTimeout
	default:
		// a unit may send several payloads or follow redirects, not one request
		timeout = 3 * requestTimeout
	}
	if timeout < time.Second {
		timeout = time.Second
	}
	return timeout
}

// executeSelfContained runs a self-contained template: with a callback it
// writes the template's results through the isolation filter, otherwise it
// executes the protocol chain directly.
func (e *Engine) executeSelfContained(runCtx context.Context, template *templates.Template) (bool, error) {
	scanCtx := scan.NewScanContext(runCtx, contextargs.New(runCtx))
	if e.Callback == nil {
		return template.Executer.Execute(scanCtx)
	}
	results, err := template.Executer.ExecuteWithResults(scanCtx)
	if err != nil {
		return false, err
	}
	sink := e.isolationRecorder().WrapResults(e.Callback)
	for _, result := range results {
		sink(result)
	}
	return true, nil
}

// runUnit executes one template on one target under isolation. A crashed,
// hung or leaking run is isolated on that target; the bounded retries are
// spent first, and a template that keeps failing on distinct targets is
// quarantined for the rest of the scan by the recorder. Every decision is
// recorded.
//
// Isolation does not change what a normal run returns or the order in which
// its results are written; it only adds a deadline and a resource boundary
// around the run.
func (e *Engine) runUnit(ctx context.Context, template *templates.Template, value *contextargs.MetaInput) (matched bool, err error) {
	// one task per pair, no matter how many attempts it took or whether it was
	// skipped after its template was isolated
	defer e.tasksDone(1)
	return e.runUnitBody(ctx, template, value, func(runCtx context.Context) (bool, error) {
		return e.executeTemplateOnInput(runCtx, template, value)
	})
}

// runUnitBody is runUnit for a caller that supplies its own body, such as the
// callback path of a self-contained template. The body runs under the same
// deadline, panic boundary and resource set.
func (e *Engine) runUnitBody(ctx context.Context, template *templates.Template, value *contextargs.MetaInput, body func(context.Context) (bool, error)) (matched bool, err error) {
	recorder := e.isolationRecorder()
	target := ""
	if value != nil {
		target = value.Input
	}
	if skip, _ := recorder.SkipTarget(template.ID, target); skip {
		recorder.CountScheduled(template.ID, 1)
		return false, errUnitSkipped
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return false, ctxErr
	}

	timeout := e.unitTimeout(template)
	attempts := recorder.Retry() + 1
	var result unitResult
	for attempt := 1; attempt <= attempts; attempt++ {
		result = e.runUnitOnce(ctx, template, value, timeout, body)
		if !result.isFault() {
			return result.matched, result.err
		}

		decision := isolation.Decision{
			Unit:     template.ID,
			Template: template.ID,
			Target:   target,
			Reason:   isolationReason(result),
			Attempt:  attempt,
			At:       time.Now(),
			Err:      unitErrorText(result),
		}
		retrying := attempt < attempts && ctx.Err() == nil
		decision.Outcome = isolation.Isolated
		if retrying {
			decision.Outcome = isolation.Recovered
		}
		quarantined := e.recordDecision(recorder, decision)

		if retrying {
			e.logDebugf("[%s] execution unit %s on %s, retrying (attempt %d/%d)", template.ID, decision.Reason, target, attempt+1, attempts)
			continue
		}

		// the retries are spent: this pair must not run again, and its late
		// writes are dropped rather than counted as findings
		recorder.QuarantineTarget(template.ID, target)
		if quarantined {
			// the template itself is now isolated for the rest of the scan
			recorder.QuarantineTemplate(template.ID)
		}
		e.noteUnitFaultOnHost(template, value, result)
		if quarantined {
			e.logWarningf("[%s] isolated for the rest of the scan after repeated failures: %s", template.ID, decision.Err)
		} else {
			e.logWarningf("[%s] isolated on %s (%s): %s", template.ID, target, decision.Reason, decision.Err)
		}
		// The caller gets the fault itself, so host-level tracking sees it and
		// the scan can tell an isolated unit from a clean run.
		if result.err != nil {
			return false, result.err
		}
		if result.leaked > 0 {
			return false, fmt.Errorf("%w: %s", isolation.ErrUnitFault, result.leakDetail)
		}
		return false, fmt.Errorf("%w: %s", isolation.ErrUnitFault, decision.Err)
	}
	return result.matched, result.err
}

// runUnitOnce runs the unit body under a deadline and a resource set. A panic
// is recovered here, never propagated to the caller's goroutine, so one
// crashing unit cannot end the scan. The result is always set.
func (e *Engine) runUnitOnce(ctx context.Context, template *templates.Template, value *contextargs.MetaInput, timeout time.Duration, body func(context.Context) (bool, error)) unitResult {
	runCtx, cancel := context.WithTimeoutCause(ctx, timeout, errUnitTimeout)
	defer cancel()

	resources := isolation.NewResources()
	runCtx = isolation.WithResources(runCtx, resources)

	done := make(chan unitResult, 1)
	go func() {
		// The unit writes its outcome even if the scan gave up waiting, so no
		// attempt is leaked. The buffered channel means the send never blocks.
		defer func() {
			if recovered := recover(); recovered != nil {
				done <- unitResult{
					reason: isolation.ReasonPanic,
					detail: fmt.Sprintf("%v", recovered),
					err:    fmt.Errorf("%w: %v", errUnitPanic, recovered),
				}
			}
		}()
		matched, err := body(runCtx)
		done <- unitResult{matched: matched, err: err}
	}()

	var result unitResult
	select {
	case result = <-done:
	case <-runCtx.Done():
		// prefer a result that raced with the deadline
		select {
		case result = <-done:
		default:
			if ctx.Err() != nil {
				// the scan itself stopped; this is not the unit's fault
				result = unitResult{err: ctx.Err()}
				break
			}
			// The unit goroutine may still be blocked. Its slot is released
			// here, its resources are reclaimed below, and the recorder drops
			// any result it writes afterwards.
			result = unitResult{
				reason: isolation.ReasonTimeout,
				detail: timeoutDetail(runCtx, timeout),
				err:    timeoutError(runCtx, timeout),
			}
		}
	}
	// A unit that returns without closing what it opened is recorded as a leak,
	// but it is not a fault worth retrying: its own result stands. Reclaim in
	// every case; a failed reclaim is recorded and the batch carries on.
	if leaked := resources.Unclosed(); leaked > 0 && result.returned() {
		result.leaked = leaked
		result.leakDetail = fmt.Sprintf("%d resource(s) left open", leaked)
	}
	for _, err := range resources.Close(e.cleanupTimeout()) {
		result.cleanupErrs = append(result.cleanupErrs, err)
	}
	return result
}

// returned reports whether the unit itself finished, rather than crashing or
// timing out.
func (r unitResult) returned() bool {
	return r.reason == ""
}

// isFault reports whether the unit must be isolated. A crash, a timeout, or a
// unit that returned while still holding resources is isolated on its target:
// its result cannot be trusted and its late writes must not reach the findings
// list. A failed reclaim alone is recorded but the unit's own result stands.
func (r unitResult) isFault() bool {
	if r.leaked > 0 {
		return true
	}
	switch r.reason {
	case isolation.ReasonPanic, isolation.ReasonTimeout:
		return true
	}
	return false
}

// noteUnitFaultOnHost counts an isolated unit toward the target's host error
// budget, so a target that keeps crashing or hanging units is skipped for the
// templates that have not reached it yet.
func (e *Engine) noteUnitFaultOnHost(template *templates.Template, value *contextargs.MetaInput, result unitResult) {
	if e.executerOpts == nil || e.executerOpts.HostErrorsCache == nil || value == nil {
		return
	}
	if result.reason == "" && len(result.cleanupErrs) == 0 {
		return
	}
	hostErrCtx := contextargs.NewWithMetaInput(context.Background(), value)
	e.executerOpts.HostErrorsCache.MarkFailedOrRemove(template.Type().String(), hostErrCtx, fmt.Errorf("%w: %s", isolation.ErrUnitFault, unitErrorText(result)))
}

// cleanupTimeout returns how long reclaiming a unit's resources may take.
func (e *Engine) cleanupTimeout() time.Duration {
	if e.options != nil && e.options.IsolationOptions != nil && e.options.IsolationOptions.CleanupTimeout > 0 {
		return e.options.IsolationOptions.CleanupTimeout
	}
	return isolation.DefaultCleanupTimeout
}

// recordDecision records one decision, reports it to the lifecycle callback,
// and returns whether the template is now quarantined for the scan.
func (e *Engine) recordDecision(recorder *isolation.Recorder, decision isolation.Decision) bool {
	_, quarantined := recorder.Record(decision)
	e.forwardDecision(decision)
	return quarantined
}

// forwardDecision passes the decision to the template execution callback, when
// one is registered, so an embedding application can audit it live.
func (e *Engine) forwardDecision(decision isolation.Decision) {
	if e.templateExecutionCallback == nil {
		return
	}
	copied := decision
	e.templateExecutionCallback(TemplateExecutionEvent{
		TemplateID: decision.Template,
		Target:     decision.Target,
		State:      TemplateExecutionFinished,
		Isolation:  &copied,
	})
}

func isolationReason(result unitResult) isolation.Reason {
	switch result.reason {
	case isolation.ReasonPanic:
		return isolation.ReasonPanic
	case isolation.ReasonTimeout:
		return isolation.ReasonTimeout
	}
	// A resource the unit left open and the reclaim also failed to close is
	// reported as a cleanup failure: that is the state an operator has to act
	// on.
	if len(result.cleanupErrs) > 0 {
		return isolation.ReasonCleanup
	}
	if result.leaked > 0 {
		return isolation.ReasonLeak
	}
	return ""
}

func unitErrorText(result unitResult) string {
	switch {
	case result.reason == isolation.ReasonPanic:
		return "panic: " + result.detail
	case result.reason == isolation.ReasonTimeout:
		return result.detail
	case len(result.cleanupErrs) > 0:
		return result.cleanupErrs[0].Error()
	case result.leaked > 0:
		return result.leakDetail
	case result.err != nil:
		return result.err.Error()
	default:
		return result.detail
	}
}

func timeoutDetail(ctx context.Context, timeout time.Duration) string {
	cause := context.Cause(ctx)
	if cause != nil && !errors.Is(cause, errUnitTimeout) {
		return fmt.Sprintf("did not return within %s: %s", timeout, cause)
	}
	return fmt.Sprintf("did not return within %s", timeout)
}

func timeoutError(ctx context.Context, timeout time.Duration) error {
	cause := context.Cause(ctx)
	if cause != nil && !errors.Is(cause, errUnitTimeout) {
		return fmt.Errorf("%w after %s: %s", errUnitTimeout, timeout, cause)
	}
	return fmt.Errorf("%w after %s", errUnitTimeout, timeout)
}

func (e *Engine) logDebugf(format string, args ...any) {
	if e.options != nil && e.options.Logger != nil {
		e.options.Logger.Debug().Msgf(format, args...)
	}
}

func (e *Engine) logWarningf(format string, args ...any) {
	if e.options != nil && e.options.Logger != nil {
		e.options.Logger.Warning().Msgf(format, args...)
	}
}
