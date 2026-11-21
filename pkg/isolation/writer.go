package isolation

import (
	"strings"
	"time"

	"github.com/logrusorgru/aurora/v4"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// Writer wraps an output writer and drops the findings of pairs the scan has
// isolated. It is installed on the runner so the CLI path, which lets
// protocols write their results directly, applies the same filter as the SDK
// callback path.
//
// A result a unit wrote before the scan learned the unit was bad has already
// been delivered and is not retracted; from the moment the pair is isolated,
// nothing more from it reaches the output. The isolation summary lists the
// pair, so a recipient filters the delivered file by that list.
type Writer struct {
	output.Writer
	recorder *Recorder
}

var _ output.Writer = &Writer{}

// NewWriter returns a writer that filters the output of isolated pairs.
func NewWriter(next output.Writer, recorder *Recorder) *Writer {
	return &Writer{Writer: next, recorder: recorder}
}

func (w *Writer) Write(event *output.ResultEvent) error {
	if w.recorder != nil && !w.recorder.FilterResult(event) {
		return nil
	}
	return w.Writer.Write(event)
}

func (w *Writer) WriteFailure(event *output.InternalWrappedEvent) error {
	if w.recorder == nil || event == nil {
		return w.Writer.WriteFailure(event)
	}
	// a failure event carries the results of an unmatched template; drop it
	// when every result belongs to an isolated pair, and otherwise pass the
	// ones that do not
	kept := event.Results[:0]
	dropped := 0
	for _, result := range event.Results {
		if w.recorder.FilterResult(result) {
			kept = append(kept, result)
		} else {
			dropped++
		}
	}
	if dropped == len(event.Results) && dropped > 0 {
		return nil
	}
	event.Results = kept
	return w.Writer.WriteFailure(event)
}

// Colorizer returns the wrapped writer's colorizer.
func (w *Writer) Colorizer() *aurora.Aurora {
	return w.Writer.Colorizer()
}

// Request forwards the request trace to the wrapped writer.
func (w *Writer) Request(templateID, url, requestType string, err error) {
	w.Writer.Request(templateID, url, requestType, err)
}

// RequestStatsLog forwards request statistics to the wrapped writer.
func (w *Writer) RequestStatsLog(statusCode, response string) {
	w.Writer.RequestStatsLog(statusCode, response)
}

// WriteStoreDebugData forwards debug data to the wrapped writer.
func (w *Writer) WriteStoreDebugData(host, templateID, eventType, data string) {
	w.Writer.WriteStoreDebugData(host, templateID, eventType, data)
}

// ResultCount returns the wrapped writer's count, minus nothing: the count is
// the wrapped writer's own.
func (w *Writer) ResultCount() int {
	return w.Writer.ResultCount()
}

// Close closes the wrapped writer.
func (w *Writer) Close() {
	w.Writer.Close()
}

// IsolatedUnitList renders the readable delivery list from a recorder. It is
// what an operator attaches to a report.
func IsolatedUnitList(recorder *Recorder) string {
	if recorder == nil {
		return "no units isolated"
	}
	summary := NewSummary(recorder, time.Now(), time.Now())
	var builder strings.Builder
	_ = summary.WriteReadable(&builder)
	return builder.String()
}
