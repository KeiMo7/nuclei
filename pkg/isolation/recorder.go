package isolation

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// ErrUnitFault marks an error that reports a crashed, hung or leaking
// execution unit. Errors wrapping it count toward a host's error budget.
var ErrUnitFault = errors.New("execution unit fault")

// Reason classifies why a unit was isolated. The classes are what the summary
// groups by and what an operator reads first.
type Reason string

const (
	// ReasonPanic is a unit that crashed: nil dereference, out-of-range index,
	// failed assertion.
	ReasonPanic Reason = "panic"
	// ReasonTimeout is a unit that did not return within the per-unit deadline,
	// including one blocked reading or waiting for a remote response.
	ReasonTimeout Reason = "timeout"
	// ReasonLeak is a unit that returned while still holding a page,
	// connection or temporary file.
	ReasonLeak Reason = "leak"
	// ReasonCleanup is a unit whose resources could not be reclaimed. It is
	// recorded and the batch continues.
	ReasonCleanup Reason = "cleanup-failed"
)

// Outcome reports the decision taken for a unit.
type Outcome string

const (
	// Isolated means the unit was removed from the results and listed.
	Isolated Outcome = "isolated"
	// Recovered means the unit crashed or hung once but stayed inside its
	// allowlist and succeeded when retried, so it is not isolated.
	Recovered Outcome = "recovered"
)

// Decision is the auditable record of one isolation event: which unit, why,
// and how many targets it affected. Decisions are keyed by unit so an operator
// can look one up after the scan.
type Decision struct {
	Unit     string    `json:"unit"`
	Template string    `json:"template"`
	Target   string    `json:"target,omitempty"`
	Reason   Reason    `json:"reason"`
	Outcome  Outcome   `json:"outcome"`
	Err      string    `json:"error,omitempty"`
	At       time.Time `json:"at"`
	// Attempt is which run of the unit produced the event, starting at 1.
	Attempt int `json:"attempt"`
}

// UnitSummary is the aggregated, per-unit view. It is what the readable list
// and the exit code are built from.
type UnitSummary struct {
	// Unit is the template ID, or the template ID with a target for a unit
	// that is isolated on that target only.
	Unit      string `json:"unit"`
	Template  string `json:"template"`
	Reason    Reason `json:"reason"`
	Isolated  bool   `json:"isolated"`
	Crashes   int    `json:"crashes"`
	Timeouts  int    `json:"timeouts"`
	Leaks     int    `json:"leaks"`
	Failures  int    `json:"cleanup-failures"`
	Recovered int    `json:"recovered"`
	// Targets is every target the unit was isolated on, sorted.
	Targets []string `json:"targets,omitempty"`
	// Affected is how many units (template x target runs) the quarantine
	// swallowed, computed by the engine because only it sees the schedule.
	Affected int `json:"affected"`
	// LastError is the most recent error text, for the readable list.
	LastError string    `json:"last-error,omitempty"`
	LastAt    time.Time `json:"last-at"`
}

// Threshold configures when repeated crashes on different targets isolate a
// template from the rest of the scan.
type Threshold struct {
	// SignatureFailures is how many targets a template may fail (crash or time
	// out) on before it is isolated for the remaining targets. A target that
	// fails twice without succeeding is isolated on that target regardless.
	SignatureFailures int
	// Retry is how many extra attempts a unit gets after a crash or timeout
	// before it is isolated on that target. It bounds the time a bad target
	// can consume.
	Retry int
	// UnitTimeout is the deadline one template run gets. Zero derives it from
	// the protocol and configured request timeout.
	UnitTimeout func(template string) time.Duration
}

// Recorder holds every decision of a scan. All methods are concurrency-safe.
type Recorder struct {
	threshold Threshold

	mu        sync.Mutex
	decisions []Decision
	units     map[string]*UnitSummary
	// failing counts distinct targets a template failed on; entries are added
	// once per target so a template is not isolated for failing the same
	// target twice.
	failing map[string]map[string]struct{}
	// quarantined holds templates isolated from the rest of the scan and
	// pairs isolated on one target only.
	quarantined map[string]struct{}
	// pairQuarantined holds "template\x00target" keys.
	pairQuarantined map[string]struct{}
	// pairHosts holds the normalized hosts of pairQuarantined, so a result
	// whose Host differs from the target as given still matches.
	pairHosts map[string]struct{}
	// affected accounts for scheduled runs a quarantine stopped.
	affected map[string]int
	// scheduled is the total runs of each template the scan planned.
	scheduled map[string]int
	started   int
}

// NewRecorder returns a recorder enforcing threshold.
func NewRecorder(threshold Threshold) *Recorder {
	if threshold.Retry < 0 {
		threshold.Retry = 0
	}
	if threshold.SignatureFailures <= 0 {
		threshold.SignatureFailures = 3
	}
	return &Recorder{
		threshold:       threshold,
		units:           make(map[string]*UnitSummary),
		failing:         make(map[string]map[string]struct{}),
		quarantined:     make(map[string]struct{}),
		pairQuarantined: make(map[string]struct{}),
		pairHosts:       make(map[string]struct{}),
		affected:        make(map[string]int),
		scheduled:       make(map[string]int),
	}
}

// Threshold returns the thresholds this recorder enforces.
func (r *Recorder) Threshold() Threshold { return r.threshold }

// UnitTimeout returns the deadline one run of template gets.
func (r *Recorder) UnitTimeout(template string) time.Duration {
	if r.threshold.UnitTimeout == nil {
		return 0
	}
	return r.threshold.UnitTimeout(template)
}

// Retry returns how many extra attempts a crashed or timed-out unit gets.
func (r *Recorder) Retry() int { return r.threshold.Retry }

func (r *Recorder) unitLocked(template string) *UnitSummary {
	summary, ok := r.units[template]
	if !ok {
		summary = &UnitSummary{Unit: template, Template: template}
		r.units[template] = summary
	}
	return summary
}

func (r *Recorder) countFailureLocked(summary *UnitSummary, reason Reason) {
	switch reason {
	case ReasonPanic:
		summary.Crashes++
	case ReasonTimeout:
		summary.Timeouts++
	case ReasonLeak:
		summary.Leaks++
	case ReasonCleanup:
		summary.Failures++
	}
}

// Record appends a decision. It returns whether the unit is isolated after
// this event and whether failure isolation happened (the template is now
// quarantined for the rest of the scan).
func (r *Recorder) Record(decision Decision) (isolated bool, quarantined bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	summary := r.unitLocked(decision.Template)
	summary.LastAt = decision.At
	summary.LastError = decision.Err
	r.countFailureLocked(summary, decision.Reason)
	r.decisions = append(r.decisions, decision)

	switch decision.Outcome {
	case Recovered:
		summary.Recovered++
		return false, r.quarantineIfThresholdLocked(decision.Template, decision.Target)
	case Isolated:
		summary.Isolated = true
		summary.Reason = decision.Reason
		if decision.Target != "" && !containsString(summary.Targets, decision.Target) {
			summary.Targets = append(summary.Targets, decision.Target)
			sort.Strings(summary.Targets)
		}
	}

	quarantined = r.quarantineIfThresholdLocked(decision.Template, decision.Target)
	return true, quarantined
}

// quarantineIfThresholdLocked quarantines a template once it failed on the
// configured number of distinct targets, and reports whether it did now.
func (r *Recorder) quarantineIfThresholdLocked(template, target string) bool {
	if target == "" {
		return false
	}
	if r.failing[template] == nil {
		r.failing[template] = make(map[string]struct{})
	}
	before := len(r.failing[template])
	r.failing[template][target] = struct{}{}
	if len(r.failing[template]) == before || len(r.failing[template]) < r.threshold.SignatureFailures {
		return false
	}
	if _, already := r.quarantined[template]; already {
		return false
	}
	r.quarantined[template] = struct{}{}
	return true
}

// settledLocked returns whether the recorder has already decided about the
// pair.
func (r *Recorder) settledLocked(template, target string) bool {
	if _, ok := r.quarantined[template]; ok {
		return true
	}
	_, ok := r.pairQuarantined[pairKey(template, target)]
	return ok
}

// IsSettled reports whether the template or the template-on-target pair was
// isolated, so no new run of it starts.
func (r *Recorder) IsSettled(template, target string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.settledLocked(template, target)
}

// IsSettledHost reports whether a result for host belongs to a pair that is
// isolated. Unlike IsSettled it is tolerant of the shapes a protocol uses for
// a result's Host: the target as given, its URL host, with or without a
// default port.
func (r *Recorder) IsSettledHost(template, host string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.quarantined[template]; ok {
		return true
	}
	if _, ok := r.pairQuarantined[pairKey(template, host)]; ok {
		return true
	}
	_, ok := r.pairHosts[pairKey(template, normalizeHost(host))]
	return ok
}

// normalizeHost reduces a target or result host to host[:port], dropping the
// scheme and any path, and folding a default port away so "https://a.test" and
// "a.test:443" name the same pair.
func normalizeHost(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if !strings.Contains(value, "://") {
		// url.Parse treats "example.com:8080" as a scheme, so parse a bare
		// host[:port] directly. Without a scheme, 80 and 443 are the only
		// defaults, and either names the same host as no port at all.
		host, port, err := net.SplitHostPort(value)
		if err == nil {
			if port == "80" || port == "443" {
				return strings.ToLower(strings.Trim(host, "[]"))
			}
			return net.JoinHostPort(strings.ToLower(strings.Trim(host, "[]")), port)
		}
		return strings.ToLower(value)
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" {
		return strings.ToLower(value)
	}
	return joinHostPort(parsed.Hostname(), parsed.Port(), parsed.Scheme)
}

func joinHostPort(host, port, scheme string) string {
	host = strings.ToLower(strings.Trim(host, "[]"))
	if port == "" {
		return host
	}
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		return host
	}
	return net.JoinHostPort(host, port)
}

// FilterResult reports whether a result belongs to a pair that is still
// running, i.e. whether it may reach the findings list. A result for a pair
// that was isolated is dropped.
func (r *Recorder) FilterResult(event *output.ResultEvent) bool {
	if event == nil {
		return false
	}
	if event.TemplateID == "" {
		// a result without a template cannot be attributed to an isolated unit
		return true
	}
	if r.IsSettledHost(event.TemplateID, event.Host) {
		return false
	}
	return true
}

// WrapResults drops results of isolated pairs before they reach the output,
// so an isolated unit never appears in the findings list. It is safe for
// concurrent use and preserves the order of the results that do pass.
func (r *Recorder) WrapResults(next func(*output.ResultEvent)) func(*output.ResultEvent) {
	if next == nil {
		next = func(*output.ResultEvent) {}
	}
	return func(event *output.ResultEvent) {
		if !r.FilterResult(event) {
			return
		}
		next(event)
	}
}

// QuarantineTarget isolates a unit on one target only, so a bad target cannot
// burn the retry budget of every template that reaches it. The isolated run is
// counted through the summary's target list, not here; CountScheduled counts
// the later runs the quarantine turns away.
func (r *Recorder) QuarantineTarget(template, target string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := pairKey(template, target)
	if _, already := r.pairQuarantined[key]; already {
		return
	}
	r.pairQuarantined[key] = struct{}{}
	if host := normalizeHost(target); host != "" {
		r.pairHosts[pairKey(template, host)] = struct{}{}
	}
}

// QuarantineTemplate isolates a template for the rest of the scan after it
// failed on too many targets. Runs already in flight are affected too.
func (r *Recorder) QuarantineTemplate(template string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.quarantined[template] = struct{}{}
}

// SkipTarget reports whether a template run on a target must not run: the
// template is isolated for the scan, or isolated on that target.
func (r *Recorder) SkipTarget(template, target string) (skip bool, reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.quarantined[template]; ok {
		return true, "template isolated after repeated failures"
	}
	if _, ok := r.pairQuarantined[pairKey(template, target)]; ok {
		return true, "unit isolated on this target"
	}
	return false, ""
}

// CountScheduled records that count runs of template were scheduled, so the
// affected total reflects what the quarantine actually swallowed rather than
// only the failures that caused it.
func (r *Recorder) CountScheduled(template string, count int) {
	if count <= 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.affected[template] += count
}

// AddScheduledTotal records the total scheduled runs of a template before the
// scan starts, without counting the still-running or already-counted ones.
func (r *Recorder) AddScheduledTotal(template string, count int) {
	if count <= 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.scheduled[template] += count
}

// Scheduled returns the total runs of a template the scan scheduled.
func (r *Recorder) Scheduled(template string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.scheduled[template]
}

// Affected returns, per template, how many runs the quarantine turned away.
// CountScheduled adds one for each run a skip path refused, so this is exactly
// what the quarantine removed, never more than was scheduled. It does not
// include the isolated runs themselves; UnitSummary.Affected adds those.
func (r *Recorder) Affected(template string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.affectedForLocked(template)
}

// Decisions returns a copy of every recorded decision.
func (r *Recorder) Decisions() []Decision {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Decision(nil), r.decisions...)
}

// Units returns the aggregated per-unit view, sorted by unit.
func (r *Recorder) Units() []UnitSummary {
	r.mu.Lock()
	defer r.mu.Unlock()

	units := make([]UnitSummary, 0, len(r.units))
	for template, summary := range r.units {
		copied := *summary
		copied.Targets = append([]string(nil), summary.Targets...)
		copied.Affected = r.affectedForLocked(template)
		units = append(units, copied)
	}
	sort.Slice(units, func(i, j int) bool { return units[i].Unit < units[j].Unit })
	return units
}

// affectedForLocked is how many runs a quarantine of template removed: the
// isolated runs plus the scheduled runs the skip path turned away.
func (r *Recorder) affectedForLocked(template string) int {
	affected := r.affected[template]
	if summary := r.units[template]; summary != nil {
		affected += len(summary.Targets)
	}
	if scheduled := r.scheduled[template]; scheduled > 0 && affected > scheduled {
		affected = scheduled
	}
	return affected
}

// IsolatedUnits returns the summaries of the isolated templates and pairs.
func (r *Recorder) IsolatedUnits() []UnitSummary {
	units := r.Units()
	isolated := make([]UnitSummary, 0, len(units))
	for _, unit := range units {
		if unit.Isolated {
			isolated = append(isolated, unit)
		}
	}
	return isolated
}

// HasIsolation reports whether anything was isolated or had a cleanup
// failure: the condition that changes the process exit code.
func (r *Recorder) HasIsolation() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.quarantined) > 0 || len(r.pairQuarantined) > 0 || len(r.units) > 0
}

func pairKey(template, target string) string {
	return template + "\x00" + target
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// EscapeKey makes a unit or target safe for a one-line readable list.
func EscapeKey(value string) string {
	out := make([]rune, 0, len(value))
	for _, char := range value {
		switch char {
		case '\n', '\r', '\t':
			out = append(out, ' ')
		default:
			out = append(out, char)
		}
	}
	return string(out)
}

// Describe renders a decision for a log line.
func (d Decision) Describe() string {
	who := d.Template
	if d.Target != "" {
		who = fmt.Sprintf("%s on %s", d.Template, d.Target)
	}
	if d.Err == "" {
		return fmt.Sprintf("%s %s (%s, attempt %d)", who, d.Outcome, d.Reason, d.Attempt)
	}
	return fmt.Sprintf("%s %s (%s, attempt %d): %s", who, d.Outcome, d.Reason, d.Attempt, d.Err)
}
