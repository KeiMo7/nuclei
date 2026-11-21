package isolation

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"
)

// Summary is the machine-readable record written next to a scan's results. It
// keeps the isolated units out of the not-found bucket and gives the totals an
// operator needs to judge the delivery.
type Summary struct {
	StartedAt time.Time `json:"started-at"`
	EndedAt   time.Time `json:"ended-at"`
	// Units is every template that crashed, hung or leaked at least once.
	Units []UnitSummary `json:"units"`
	// Isolated is the subset the scan removed from the results.
	Isolated []UnitSummary `json:"isolated"`
	// Decisions is the per-event audit trail, keyed by unit.
	Decisions []Decision `json:"decisions"`
}

// NewSummary snapshots recorder after a scan.
func NewSummary(recorder *Recorder, startedAt, endedAt time.Time) Summary {
	if recorder == nil {
		return Summary{StartedAt: startedAt, EndedAt: endedAt}
	}
	units := recorder.Units()
	decisions := recorder.Decisions()
	isolated := make([]UnitSummary, 0, len(units))
	for _, unit := range units {
		if unit.Isolated {
			isolated = append(isolated, unit)
		}
	}
	return Summary{
		StartedAt: startedAt,
		EndedAt:   endedAt,
		Units:     units,
		Isolated:  isolated,
		Decisions: decisions,
	}
}

// Empty reports whether the scan isolated nothing and saw no failures.
func (s Summary) Empty() bool {
	return len(s.Units) == 0 && len(s.Decisions) == 0
}

// IsolatedNothing reports whether the scan completed without isolating a unit.
// A cleanup failure alone still counts: the delivery is not fully verified.
func (s Summary) IsolatedNothing() bool {
	return len(s.Isolated) == 0 && len(s.Units) == 0
}

// WriteJSON writes the summary as one JSON object.
func (s Summary) WriteJSON(w io.Writer) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(s)
}

// MarshalJSON keeps the summary diffable across runs: the audit trail is
// ordered by unit, then by time, so two identical scans produce the same file.
// The wall-clock fields (StartedAt, EndedAt, LastAt) are still per-run; a
// caller comparing two runs compares Units, Isolated and Decisions.
func (s Summary) MarshalJSON() ([]byte, error) {
	type summaryAlias Summary
	copied := summaryAlias(s)
	copied.Decisions = append([]Decision(nil), s.Decisions...)
	sort.SliceStable(copied.Decisions, func(i, j int) bool {
		a, b := copied.Decisions[i], copied.Decisions[j]
		if a.Unit != b.Unit {
			return a.Unit < b.Unit
		}
		if a.Attempt != b.Attempt {
			return a.Attempt < b.Attempt
		}
		return a.At.Before(b.At)
	})
	return json.Marshal(copied)
}

// WriteReadable writes the delivery list: one line per isolated unit with its
// reason and how many targets it affected, so a recipient can see which
// targets still need a manual scan. The format is stable and diffable.
func (s Summary) WriteReadable(w io.Writer) error {
	if len(s.Isolated) == 0 {
		_, err := fmt.Fprintln(w, "no units isolated")
		return err
	}
	if _, err := fmt.Fprintln(w, "# isolated units (rescan these targets manually)"); err != nil {
		return err
	}
	for _, unit := range s.Isolated {
		targets := unit.Targets
		if len(targets) == 0 {
			targets = []string{""}
		}
		for _, target := range targets {
			if _, err := fmt.Fprintf(w, "%s\ttemplate=%s\treason=%s\ttarget=%s\taffected=%d\terror=%s\n",
				EscapeKey(unit.Unit), EscapeKey(unit.Template), unit.Reason,
				EscapeKey(target), unit.Affected, EscapeKey(unit.LastError)); err != nil {
				return err
			}
		}
	}
	return nil
}
