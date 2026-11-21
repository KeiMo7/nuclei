// Package isolation contains the bookkeeping for execution units that crash,
// hang or hold resources past their end. It lets the engine keep running the
// rest of a scan and leaves an auditable record of every decision.
package isolation

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultCleanupTimeout bounds how long reclaiming the resources of an
// isolated unit may take before the scan moves on. A cleanup that exceeds it
// is recorded and the batch continues.
const DefaultCleanupTimeout = 5 * time.Second

// Resources collects the closers an execution unit owns. The unit tracks a
// page, a connection or a temporary file as soon as it acquires it, so the
// isolation layer can reclaim it when the unit panics or times out. Tracking
// is concurrency-safe: a unit may open resources from several goroutines.
type Resources struct {
	mu      sync.Mutex
	entries []*resourceEntry
	closed  bool
}

type resourceEntry struct {
	name  string
	close func() error
	once  sync.Once
	done  atomic.Bool
	err   error
}

// NewResources returns an empty resource set for one execution unit.
func NewResources() *Resources {
	return &Resources{}
}

// Track adds a closer and returns a release func the unit calls after it
// closed the resource itself. The release marks the resource reclaimed, so a
// unit that cleans up normally is not reported as leaking; the unit's own
// close stays authoritative. A resource without its release stays open from
// the set's point of view, so the isolation layer closes it when the unit
// crashes, hangs or returns without cleaning up.
//
// Releasing is idempotent and concurrency-safe. A closer added after the set
// was closed runs immediately, and its release is a no-op.
func (r *Resources) Track(name string, closeFunc func() error) (release func()) {
	if closeFunc == nil {
		return func() {}
	}
	entry := &resourceEntry{name: name, close: closeFunc}

	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		entry.once.Do(func() {
			entry.err = entry.close()
			entry.done.Store(true)
		})
		return func() {}
	}
	r.entries = append(r.entries, entry)
	r.mu.Unlock()

	return func() {
		entry.done.Store(true)
	}
}

// Unclosed reports how many tracked resources were not closed yet. The engine
// asks before it closes the set, to detect a unit that returned normally while
// still holding something.
func (r *Resources) Unclosed() int {
	r.mu.Lock()
	entries := append([]*resourceEntry(nil), r.entries...)
	r.mu.Unlock()

	var count int
	for _, entry := range entries {
		if !entry.done.Load() {
			count++
		}
	}
	return count
}

// Close closes every tracked resource in reverse order. It returns the errors
// of the closers that failed, plus a timeout error when the whole cleanup did
// not finish within timeout. Callers record these and continue; a failed
// reclaim never ends the batch. Close is safe to call more than once.
func (r *Resources) Close(timeout time.Duration) []error {
	r.mu.Lock()
	alreadyClosed := r.closed
	r.closed = true
	entries := append([]*resourceEntry(nil), r.entries...)
	r.mu.Unlock()

	if alreadyClosed {
		return nil
	}
	if timeout <= 0 {
		timeout = DefaultCleanupTimeout
	}

	done := make(chan []error, 1)
	go func() {
		var errs []error
		for i := len(entries) - 1; i >= 0; i-- {
			entry := entries[i]
			// a resource the unit released was closed by the unit itself
			if entry.done.Load() {
				continue
			}
			entry.once.Do(func() {
				entry.err = entry.close()
				entry.done.Store(true)
			})
			if entry.err != nil {
				errs = append(errs, &resourceError{name: entry.name, err: entry.err})
			}
		}
		done <- errs
	}()

	select {
	case errs := <-done:
		return errs
	case <-time.After(timeout):
		return []error{&resourceError{name: "cleanup", err: errCleanupTimeout}}
	}
}

type resourceError struct {
	name string
	err  error
}

func (e *resourceError) Error() string {
	return "could not reclaim " + e.name + ": " + e.err.Error()
}

func (e *resourceError) Unwrap() error {
	return e.err
}

var errCleanupTimeout = &cleanupTimeoutError{}

type cleanupTimeoutError struct{}

func (*cleanupTimeoutError) Error() string { return "resource cleanup timed out" }

// IsCleanupTimeout reports whether err is the timeout Close returns when a
// closer hangs.
func IsCleanupTimeout(err error) bool {
	_, ok := err.(*cleanupTimeoutError)
	return ok
}

type resourcesKey struct{}

// WithResources attaches the resource set of the current execution unit to
// ctx. Protocols call it to register cleanup without knowing about isolation.
func WithResources(ctx context.Context, resources *Resources) context.Context {
	return context.WithValue(ctx, resourcesKey{}, resources)
}

// ResourcesFrom returns the resource set attached to ctx, or nil.
func ResourcesFrom(ctx context.Context) *Resources {
	resources, _ := ctx.Value(resourcesKey{}).(*Resources)
	return resources
}

// TrackResource registers a closer for the execution unit running under ctx
// and returns a release func the caller invokes once it closed the resource
// itself. It reports false when no resource set is attached, in which case the
// release is a no-op.
func TrackResource(ctx context.Context, name string, closeFunc func() error) (registered bool, release func()) {
	resources := ResourcesFrom(ctx)
	if resources == nil {
		return false, func() {}
	}
	return true, resources.Track(name, closeFunc)
}
