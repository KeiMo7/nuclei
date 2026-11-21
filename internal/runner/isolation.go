package runner

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/core"
	"github.com/projectdiscovery/nuclei/v3/pkg/exitcode"
	"github.com/projectdiscovery/nuclei/v3/pkg/isolation"
	isolationtypes "github.com/projectdiscovery/nuclei/v3/pkg/isolation/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

// isolationSummarySuffix is appended to the output file to name the machine
// readable isolation summary written next to it.
const isolationSummarySuffix = ".isolation.json"

// isolationReportSuffix is appended to the output file to name the readable
// list of isolated units.
const isolationReportSuffix = ".isolation.txt"

// installIsolation configures the engine's recorder from the scan options and
// keeps the recorder on the runner for the after-scan summary. The runner's
// output writer already filters by the same recorder, installed when the
// writer was built.
func (r *Runner) installIsolation(engine *core.Engine) {
	if r.recorder == nil {
		options := isolationOptions(r.options)
		threshold := isolation.Threshold{
			Retry:             options.RetryCount(),
			SignatureFailures: options.SignatureThreshold(),
		}
		if isSignatureIsolationDisabled(r.options) {
			// A template is never removed for failing on many targets;
			// per-target isolation still applies.
			threshold.SignatureFailures = 1 << 30
		}
		r.recorder = isolation.NewRecorder(threshold)
	}
	r.scanStarted = time.Now()
	if engine != nil {
		engine.SetIsolationRecorder(r.recorder)
	}
}

// isSignatureIsolationDisabled reports whether a template must never be
// isolated for failing on many targets.
func isSignatureIsolationDisabled(options *types.Options) bool {
	return options != nil && options.IsolationOptions != nil && options.IsolationOptions.DisableSignatureIsolation
}

// isolationOptions returns the scan's isolation options, defaulting when the
// embedded caller did not set them.
func isolationOptions(options *types.Options) *isolationtypes.Options {
	if options != nil && options.IsolationOptions != nil {
		return options.IsolationOptions
	}
	return isolationtypes.DefaultOptions()
}

// finishIsolation snapshots the recorder, writes the audit files, and leaves
// the summary where the caller reads it for the exit status.
func (r *Runner) finishIsolation(engine *core.Engine) {
	recorder := r.recorder
	if recorder == nil && engine != nil {
		recorder = engine.IsolationRecorder()
	}
	r.isolation = isolation.NewSummary(recorder, r.scanStarted, time.Now())
	if r.isolation.IsolatedNothing() {
		return
	}
	r.logIsolationSummary()

	outputPath := r.isolationOutputPath()
	if outputPath == "" {
		r.Logger.Warning().Msgf("Units were isolated but no output file is configured; the isolation list was only logged. Use -json-export, -jsonl-export or -isolation-report to keep it")
		return
	}
	if err := r.writeIsolationFiles(outputPath); err != nil {
		r.Logger.Error().Msgf("Could not write the isolation summary: %s", err)
	}
}

// logIsolationSummary reports the isolated classes separately from not-found,
// so a delivery is not read as fully scanned.
func (r *Runner) logIsolationSummary() {
	isolated := len(r.isolation.Isolated)
	var affected int
	for _, unit := range r.isolation.Isolated {
		affected += unit.Affected
	}
	if affected == 0 {
		// affected counts only what ran after a quarantine; the crashing runs
		// themselves are the failed units
		affected = len(r.isolation.Isolated)
	}
	r.Logger.Warning().Msgf("%d unit(s) isolated, %d template-target run(s) affected: these are not not-found results and their targets need a manual rescan", isolated, affected)
}

// isolationOutputPath returns where to write the summary and the readable list.
// An explicit report path wins; otherwise the files sit next to the JSON
// output the scan already writes.
func (r *Runner) isolationOutputPath() string {
	if r.options.IsolationReportPath != "" {
		return r.options.IsolationReportPath
	}
	if r.options != nil && r.options.IsolationOptions != nil && r.options.IsolationOptions.ReportPath != "" {
		return r.options.IsolationOptions.ReportPath
	}
	output := r.options.JSONLExport
	if output == "" {
		output = r.options.JSONExport
	}
	if output == "" {
		output = r.options.Output
	}
	if output == "" {
		return ""
	}
	return output
}

// writeIsolationFiles writes the JSON summary and the readable list. Failure
// to write either is reported and does not change the scan's outcome.
func (r *Runner) writeIsolationFiles(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
		return err
	}
	summaryPath := path + isolationSummarySuffix
	file, err := os.Create(summaryPath)
	if err != nil {
		return err
	}
	buffered := bufio.NewWriter(file)
	writeErr := r.isolation.WriteJSON(buffered)
	if writeErr == nil {
		writeErr = buffered.Flush()
	}
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}

	reportPath := path + isolationReportSuffix
	report, err := os.Create(reportPath)
	if err != nil {
		return err
	}
	buffered = bufio.NewWriter(report)
	writeErr = r.isolation.WriteReadable(buffered)
	if writeErr == nil {
		writeErr = buffered.Flush()
	}
	closeErr = report.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	r.Logger.Info().Msgf("Isolation summary written to %s and readable list to %s", summaryPath, reportPath)
	return nil
}

// IsolationStatus returns the exit status the last scan earned. The CLI exits
// with it after a completed run: zero when nothing was isolated, partial when
// units were.
func (r *Runner) IsolationStatus() exitcode.Status {
	return exitcode.FromSummary(r.isolation)
}

// IsolationSummary returns the last scan's isolation summary.
func (r *Runner) IsolationSummary() isolation.Summary {
	return r.isolation
}

// formatIsolationCounts renders the per-class counts for the summary log.
func formatIsolationCounts(summary isolation.Summary) string {
	return fmt.Sprintf("panic=%d timeout=%d leak=%d cleanup=%d",
		countReason(summary, isolation.ReasonPanic),
		countReason(summary, isolation.ReasonTimeout),
		countReason(summary, isolation.ReasonLeak),
		countReason(summary, isolation.ReasonCleanup))
}

func countReason(summary isolation.Summary, reason isolation.Reason) int {
	count := 0
	for _, decision := range summary.Decisions {
		if decision.Reason != reason || decision.Outcome != isolation.Isolated {
			continue
		}
		count++
	}
	return count
}
