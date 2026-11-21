package isolation_test

import (
	"testing"

	"github.com/logrusorgru/aurora/v4"
	"github.com/projectdiscovery/nuclei/v3/pkg/isolation"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/stretchr/testify/require"
)

type stubWriter struct {
	written []*output.ResultEvent
	failed  int
}

func (s *stubWriter) Close()                    {}
func (s *stubWriter) Colorizer() *aurora.Aurora { return aurora.New(aurora.WithColors(false)) }
func (s *stubWriter) Write(event *output.ResultEvent) error {
	s.written = append(s.written, event)
	return nil
}
func (s *stubWriter) WriteFailure(event *output.InternalWrappedEvent) error { s.failed++; return nil }
func (s *stubWriter) Request(string, string, string, error)                 {}
func (s *stubWriter) RequestStatsLog(string, string)                        {}
func (s *stubWriter) WriteStoreDebugData(string, string, string, string)    {}
func (s *stubWriter) ResultCount() int                                      { return len(s.written) }

func TestWriterDropsIsolatedFindings(t *testing.T) {
	recorder := isolation.NewRecorder(isolation.Threshold{Retry: 0, SignatureFailures: 3})
	recorder.Record(isolation.Decision{Unit: "t", Template: "t", Target: "https://a.test", Reason: isolation.ReasonPanic, Outcome: isolation.Isolated})
	recorder.QuarantineTarget("t", "https://a.test")

	next := &stubWriter{}
	writer := isolation.NewWriter(next, recorder)

	// the CLI path writes results directly; the isolated pair's result must not
	// reach the next writer
	require.NoError(t, writer.Write(&output.ResultEvent{TemplateID: "t", Host: "https://a.test"}))
	require.NoError(t, writer.Write(&output.ResultEvent{TemplateID: "t", Host: "https://b.test"}))
	require.NoError(t, writer.Write(&output.ResultEvent{TemplateID: "other", Host: "https://a.test"}))
	require.Len(t, next.written, 2)
	require.Equal(t, "https://b.test", next.written[0].Host)
	require.Equal(t, "other", next.written[1].TemplateID)
}

func TestWriterMatchesResultHostShape(t *testing.T) {
	recorder := isolation.NewRecorder(isolation.Threshold{SignatureFailures: 3})
	recorder.QuarantineTarget("t", "https://a.test")

	next := &stubWriter{}
	writer := isolation.NewWriter(next, recorder)
	// a protocol may report the bare host of the target it was given
	for _, host := range []string{"a.test", "a.test:443", "https://a.test/path"} {
		require.NoError(t, writer.Write(&output.ResultEvent{TemplateID: "t", Host: host}))
	}
	require.Empty(t, next.written, "every shape of the isolated target's host must be filtered")
}

func TestWriterPassesFailuresOfRunningPairs(t *testing.T) {
	recorder := isolation.NewRecorder(isolation.Threshold{SignatureFailures: 3})
	recorder.QuarantineTarget("t", "https://a.test")

	next := &stubWriter{}
	writer := isolation.NewWriter(next, recorder)

	isolated := &output.InternalWrappedEvent{Results: []*output.ResultEvent{{TemplateID: "t", Host: "https://a.test"}}}
	require.NoError(t, writer.WriteFailure(isolated))
	require.Zero(t, next.failed, "a failure event made only of isolated results is dropped")

	mixed := &output.InternalWrappedEvent{Results: []*output.ResultEvent{
		{TemplateID: "t", Host: "https://a.test"},
		{TemplateID: "t", Host: "https://b.test"},
	}}
	require.NoError(t, writer.WriteFailure(mixed))
	require.Equal(t, 1, next.failed)
	require.Len(t, mixed.Results, 1)
}

func TestWriterWithoutRecorderPassesEverything(t *testing.T) {
	next := &stubWriter{}
	writer := isolation.NewWriter(next, nil)
	require.NoError(t, writer.Write(&output.ResultEvent{TemplateID: "t", Host: "https://a.test"}))
	require.Len(t, next.written, 1)
}

func TestWriterForwardsCloseAndCount(t *testing.T) {
	next := &stubWriter{}
	writer := isolation.NewWriter(next, isolation.NewRecorder(isolation.Threshold{}))
	writer.Close()
	require.Equal(t, 0, writer.ResultCount())
}
