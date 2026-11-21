package exitcode_test

import (
	"errors"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/exitcode"
	"github.com/projectdiscovery/nuclei/v3/pkg/isolation"
)

func TestStatusesAreDistinct(t *testing.T) {
	if exitcode.OK == exitcode.Failure || exitcode.OK == exitcode.Partial || exitcode.Failure == exitcode.Partial {
		t.Fatal("exit statuses must not collide")
	}
}

func TestFromSummary(t *testing.T) {
	if got := exitcode.FromSummary(isolation.Summary{}); got != exitcode.OK {
		t.Fatalf("empty summary status = %d, want OK", got)
	}
	summary := isolation.Summary{
		Units:    []isolation.UnitSummary{{Unit: "tpl", Isolated: true}},
		Isolated: []isolation.UnitSummary{{Unit: "tpl", Isolated: true}},
	}
	if got := exitcode.FromSummary(summary); got != exitcode.Partial {
		t.Fatalf("status with an isolated unit = %d, want Partial", got)
	}
}

func TestFromError(t *testing.T) {
	if got := exitcode.FromError(errors.New("boom")); got != exitcode.Failure {
		t.Fatalf("status = %d, want Failure", got)
	}
	if got := exitcode.FromError(nil); got != exitcode.OK {
		t.Fatalf("status = %d, want OK", got)
	}
}

func TestExitCallsInjectedFunc(t *testing.T) {
	var got int
	restore := exitcode.SetExitFunc(func(code int) { got = code })
	defer restore()

	exitcode.Exit(exitcode.Partial)
	if got != int(exitcode.Partial) {
		t.Fatalf("exit code = %d, want %d", got, int(exitcode.Partial))
	}
}

func TestSummaryIsolatedNothingCountsCleanupOnly(t *testing.T) {
	summary := isolation.Summary{Units: []isolation.UnitSummary{{
		Unit: "tpl", Failures: 1,
	}}}
	if summary.IsolatedNothing() {
		t.Fatal("a unit with failures must not read as a clean scan")
	}
	_ = time.Now()
}
