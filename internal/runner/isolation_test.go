package runner

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/isolation"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestSummaryFilesAreWrittenNextToOutput(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, "results.jsonl")
	require.NoError(t, os.WriteFile(output, nil, 0o644))

	runner := &Runner{options: &types.Options{JSONLExport: output}, Logger: gologger.DefaultLogger}
	recorder := isolation.NewRecorder(isolation.Threshold{})
	recorder.Record(isolation.Decision{
		Unit: "tpl", Template: "tpl", Target: "https://x.test",
		Reason: isolation.ReasonTimeout, Outcome: isolation.Isolated,
	})
	runner.recorder = recorder
	runner.isolation = isolation.NewSummary(recorder, time.Time{}, time.Time{})

	require.Equal(t, output, runner.isolationOutputPath())
	require.NoError(t, runner.writeIsolationFiles(output))

	summaryFile, err := os.ReadFile(output + isolationSummarySuffix)
	require.NoError(t, err)
	require.Contains(t, string(summaryFile), `"isolated"`)

	listFile, err := os.ReadFile(output + isolationReportSuffix)
	require.NoError(t, err)
	require.Contains(t, string(listFile), "template=tpl")
}

func TestExplicitReportPathWins(t *testing.T) {
	runner := &Runner{options: &types.Options{
		JSONLExport:         "/tmp/results.jsonl",
		IsolationReportPath: "/tmp/isolation.txt",
	}}
	require.Equal(t, "/tmp/isolation.txt", runner.isolationOutputPath())
}

func TestMissingOutputDisablesFiles(t *testing.T) {
	runner := &Runner{options: &types.Options{}}
	require.Empty(t, runner.isolationOutputPath())
}
