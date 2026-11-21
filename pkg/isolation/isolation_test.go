package isolation_test

import (
	"bytes"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/isolation"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/stretchr/testify/require"
)

func TestResourcesCloseIsLIFOAndIdempotent(t *testing.T) {
	resources := isolation.NewResources()
	var order []string
	resources.Track("first", func() error {
		order = append(order, "first")
		return nil
	})
	resources.Track("second", func() error {
		order = append(order, "second")
		return nil
	})
	require.Equal(t, 2, resources.Unclosed())

	require.Empty(t, resources.Close(0))
	require.Equal(t, []string{"second", "first"}, order)

	// closing twice, or tracking after close, is harmless: the unit's own
	// defers may close a resource the isolation layer already reclaimed
	require.Empty(t, resources.Close(0))
	resources.Track("late", func() error {
		order = append(order, "late")
		return nil
	})
	require.Equal(t, []string{"second", "first", "late"}, order)
}

func TestResourcesReleaseMarksReclaimed(t *testing.T) {
	resources := isolation.NewResources()
	closed := false
	release := resources.Track("page", func() error {
		closed = true
		return nil
	})
	require.Equal(t, 1, resources.Unclosed())

	// a unit that closes normally is not a leak, and the isolation layer must
	// not close the resource a second time
	release()
	require.Zero(t, resources.Unclosed())
	require.Empty(t, resources.Close(0))
	require.False(t, closed, "a released resource is not reclaimed by the set")

	// releasing twice is harmless
	release()
}

func TestResourcesReportsOnlyUnreleasedLeftovers(t *testing.T) {
	resources := isolation.NewResources()
	kept := resources.Track("kept", func() error { return nil })
	resources.Track("left", func() error { return nil })
	kept()
	require.Equal(t, 1, resources.Unclosed(), "only the resource the unit did not close is a leftover")
	require.Empty(t, resources.Close(0))
}

func TestResourcesRecordsCleanupFailures(t *testing.T) {
	resources := isolation.NewResources()
	resources.Track("stuck", func() error { return errors.New("refused") })
	errs := resources.Close(0)
	require.Len(t, errs, 1)
	require.Contains(t, errs[0].Error(), "stuck")
	require.Contains(t, errs[0].Error(), "refused")
}

func TestResourcesCloseTimesOut(t *testing.T) {
	resources := isolation.NewResources()
	release := make(chan struct{})
	resources.Track("hung", func() error {
		<-release
		return nil
	})
	defer close(release)

	errs := resources.Close(20 * time.Millisecond)
	require.Len(t, errs, 1)
	require.Contains(t, errs[0].Error(), "timed out")
}

func TestResourcesFromContext(t *testing.T) {
	resources := isolation.NewResources()
	ctx := isolation.WithResources(t.Context(), resources)

	closed := false
	registered, release := isolation.TrackResource(ctx, "page", func() error {
		closed = true
		return nil
	})
	require.True(t, registered)
	registered, noRelease := isolation.TrackResource(t.Context(), "page", func() error { return nil })
	require.False(t, registered, "no set means nothing to track")
	noRelease()

	release()
	require.Empty(t, resources.Close(0))
	require.False(t, closed)
}

func TestRecorderCountsTargetsAndQuarantines(t *testing.T) {
	recorder := isolation.NewRecorder(isolation.Threshold{Retry: 0, SignatureFailures: 2})
	isolated, quarantined := recorder.Record(isolation.Decision{
		Unit: "tpl", Template: "tpl", Target: "a", Reason: isolation.ReasonPanic, Outcome: isolation.Isolated,
	})
	require.True(t, isolated)
	require.False(t, quarantined)

	isolated, quarantined = recorder.Record(isolation.Decision{
		Unit: "tpl", Template: "tpl", Target: "b", Reason: isolation.ReasonTimeout, Outcome: isolation.Isolated,
	})
	require.True(t, isolated)
	require.True(t, quarantined)

	// the same target twice is still one target
	other := isolation.NewRecorder(isolation.Threshold{SignatureFailures: 2})
	other.Record(isolation.Decision{Unit: "tpl", Template: "tpl", Target: "a", Reason: isolation.ReasonPanic, Outcome: isolation.Isolated})
	_, quarantined = other.Record(isolation.Decision{Unit: "tpl", Template: "tpl", Target: "a", Reason: isolation.ReasonPanic, Outcome: isolation.Isolated})
	require.False(t, quarantined)
}

func TestRecorderRepeatedResultsAndTargets(t *testing.T) {
	recorder := isolation.NewRecorder(isolation.Threshold{SignatureFailures: 5})
	for _, target := range []string{"b", "a", "b"} {
		recorder.Record(isolation.Decision{Unit: "tpl", Template: "tpl", Target: target, Reason: isolation.ReasonPanic, Outcome: isolation.Isolated})
	}
	units := recorder.Units()
	require.Len(t, units, 1)
	require.Equal(t, []string{"a", "b"}, units[0].Targets, "targets are sorted and unique")
	require.Equal(t, 3, units[0].Crashes)
}

func TestRecorderFiltersIsolatedResults(t *testing.T) {
	recorder := isolation.NewRecorder(isolation.Threshold{Retry: 0})
	recorder.Record(isolation.Decision{Unit: "tpl", Template: "tpl", Target: "a", Reason: isolation.ReasonPanic, Outcome: isolation.Isolated})
	recorder.QuarantineTarget("tpl", "a")

	require.False(t, recorder.FilterResult(&output.ResultEvent{TemplateID: "tpl", Host: "a"}), "an isolated pair's result is dropped")
	require.True(t, recorder.FilterResult(&output.ResultEvent{TemplateID: "tpl", Host: "b"}))
	require.True(t, recorder.FilterResult(&output.ResultEvent{TemplateID: "other", Host: "a"}))

	var seen []string
	sink := recorder.WrapResults(func(event *output.ResultEvent) { seen = append(seen, event.Host) })
	sink(&output.ResultEvent{TemplateID: "tpl", Host: "a"})
	sink(&output.ResultEvent{TemplateID: "tpl", Host: "b"})
	require.Equal(t, []string{"b"}, seen)
}

func TestRecorderIsConcurrentSafe(t *testing.T) {
	recorder := isolation.NewRecorder(isolation.Threshold{Retry: 0})
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			recorder.Record(isolation.Decision{
				Unit: "tpl", Template: "tpl", Target: string(rune('a' + index%10)),
				Reason: isolation.ReasonPanic, Outcome: isolation.Isolated,
			})
			recorder.FilterResult(&output.ResultEvent{TemplateID: "tpl", Host: "a"})
			_ = recorder.Units()
			_ = recorder.Decisions()
		}(i)
	}
	wg.Wait()
	require.Len(t, recorder.Decisions(), 50)
}

func TestSummaryReadableListIsStable(t *testing.T) {
	recorder := isolation.NewRecorder(isolation.Threshold{SignatureFailures: 5})
	recorder.Record(isolation.Decision{"b.tpl", "b.tpl", "http://b", isolation.ReasonPanic, isolation.Isolated, "panic: boom", time.Unix(1, 0), 1})
	recorder.Record(isolation.Decision{"a.tpl", "a.tpl", "http://a", isolation.ReasonTimeout, isolation.Isolated, "timed out", time.Unix(2, 0), 1})
	recorder.AddScheduledTotal("a.tpl", 7)
	// the quarantine turned four of the seven scheduled runs away; one run was
	// isolated on its target
	for i := 0; i < 3; i++ {
		recorder.CountScheduled("a.tpl", 1)
	}

	summary := isolation.NewSummary(recorder, time.Unix(0, 0), time.Unix(3, 0))
	var out bytes.Buffer
	require.NoError(t, summary.WriteReadable(&out))
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	require.Len(t, lines, 3)
	require.Contains(t, lines[1], "template=a.tpl")
	require.Contains(t, lines[1], "affected=4")
	require.Contains(t, lines[2], "template=b.tpl")

	var jsonOut bytes.Buffer
	require.NoError(t, summary.WriteJSON(&jsonOut))
	require.Contains(t, jsonOut.String(), `"isolated"`)
}

func TestSummaryEmpty(t *testing.T) {
	recorder := isolation.NewRecorder(isolation.Threshold{})
	summary := isolation.NewSummary(recorder, time.Unix(0, 0), time.Unix(1, 0))
	require.True(t, summary.IsolatedNothing())
	var out bytes.Buffer
	require.NoError(t, summary.WriteReadable(&out))
	require.Equal(t, "no units isolated\n", out.String())
}
