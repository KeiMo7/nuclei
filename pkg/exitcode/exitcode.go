// Package exitcode reports how a scan ended in the process exit status. The
// status separates an overall failure from a run that completed while
// isolating some units, so a caller never reads a partial scan as a full one.
package exitcode

import (
	"os"

	"github.com/projectdiscovery/nuclei/v3/pkg/isolation"
)

// Status is a scan's process exit status.
type Status int

const (
	// OK is a scan that ran to the end with nothing isolated.
	OK Status = 0
	// Failure is a scan that could not run or ended early: setup errors,
	// validation errors, an interrupted scan.
	Failure Status = 1
	// Partial is a scan that ran to the end but isolated one or more units.
	// Its findings are complete for what ran, not for every target.
	Partial Status = 2
)

// exitFunc is replaceable in tests so a scan can assert its status without
// ending the test process.
var exitFunc = os.Exit

// SetExitFunc replaces the process exit function; tests use it and restore it
// with the returned func.
func SetExitFunc(fn func(int)) (restore func()) {
	previous := exitFunc
	exitFunc = fn
	return func() { exitFunc = previous }
}

// Exit ends the process with status.
func Exit(status Status) {
	exitFunc(int(status))
}

// FromSummary returns the status a completed scan earned. An interrupted scan
// is not a success even when isolation recorded nothing.
func FromSummary(summary isolation.Summary) Status {
	if summary.IsolatedNothing() {
		return OK
	}
	return Partial
}

// FromError returns Failure for a non-nil error, before any isolation status is
// considered: a scan that could not run is a failure, not a partial result.
func FromError(err error) Status {
	if err != nil {
		return Failure
	}
	return OK
}
