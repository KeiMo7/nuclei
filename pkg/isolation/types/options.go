// Package types holds the configuration of execution-unit isolation. It is a
// leaf package so pkg/types and pkg/isolation can both depend on it without a
// cycle.
package types

import "time"

// Options configures how the engine isolates an execution unit that crashes,
// hangs or leaks resources.
//
// Isolation is always on: a crash in one unit must never take down the scan.
// These options only tune when a repeatedly failing unit is removed from the
// rest of the scan and where the audit trail is written.
type Options struct {
	// DisableSignatureIsolation keeps a template that fails on many targets
	// from being removed from the scan. Per-target isolation still applies.
	DisableSignatureIsolation bool
	// SignatureFailures is how many distinct targets a template may fail on
	// before it is isolated for the remaining targets. Zero uses the default.
	SignatureFailures int
	// Retry is how many extra attempts a crashed or timed-out unit gets before
	// it is isolated on that target. Zero (the default) isolates on the first
	// fault, which also avoids re-writing findings a faulted attempt already
	// produced. Set it only when a fault is expected to be transient.
	Retry int
	// UnitTimeout overrides the per-unit deadline. Zero derives it from the
	// template protocol and the configured request timeout.
	UnitTimeout time.Duration
	// CleanupTimeout bounds reclaiming a unit's resources. Zero uses the
	// default; a cleanup that exceeds it is recorded and the batch continues.
	CleanupTimeout time.Duration
	// ReportPath is where to write the readable list of isolated units. Empty
	// means one is written next to the output file when the output file
	// supports a JSON summary, or no list otherwise.
	ReportPath string
}

// DefaultSignatureFailures is how many distinct targets a template may fail on
// before it is isolated from the rest of the scan.
const DefaultSignatureFailures = 3

// DefaultRetry is how many extra attempts a unit gets after a crash or
// timeout. Faults are not retried by default: the process is already in an
// unknown state, and a retry can write findings the faulted attempt produced.
const DefaultRetry = 0

// DefaultOptions returns the isolation defaults.
func DefaultOptions() *Options {
	return &Options{
		SignatureFailures: DefaultSignatureFailures,
		Retry:             DefaultRetry,
	}
}

// SignatureThreshold returns the configured failure threshold, or the default.
func (o *Options) SignatureThreshold() int {
	if o == nil || o.SignatureFailures <= 0 {
		return DefaultSignatureFailures
	}
	return o.SignatureFailures
}

// RetryCount returns the configured retry count. Zero is a valid value: it
// isolates a faulted unit on its first fault.
func (o *Options) RetryCount() int {
	if o == nil || o.Retry <= 0 {
		return 0
	}
	return o.Retry
}
