package variables

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"sync"
)

var (
	// ErrResolverClosed is returned by Resolve after the Resolver was closed.
	ErrResolverClosed = errors.New("variables: resolver closed")
	// ErrResolvePanic wraps any panic raised by a build function; the process
	// keeps running and nothing is cached for the failed key.
	ErrResolvePanic = errors.New("variables: resolve build panicked")
)

// DefaultResolverLimit is the default maximum number of resolved entries kept
// by a Resolver before least-recently-used eviction kicks in.
const DefaultResolverLimit = 4096

// ResolveKey identifies one resolvable value. TemplateID, TargetHash, and
// RequestID form the entry identity; Generation expresses invalidation, so a
// caller that bumps Generation forces a rebuild while older-generation entries
// are dropped on next access.
type ResolveKey struct {
	TemplateID string
	TargetHash string
	RequestID  string
	Generation uint64
}

// resolveIdentity is the map identity of a ResolveKey without its generation.
type resolveIdentity struct {
	templateID string
	targetHash string
	requestID  string
}

// identity returns the generation-independent identity of the key.
func (k ResolveKey) identity() resolveIdentity {
	return resolveIdentity{templateID: k.TemplateID, targetHash: k.TargetHash, requestID: k.RequestID}
}

// resolveEntry is one resolver entry. Its lifecycle is: created (building),
// then ready once done is closed, then invalidated either explicitly through
// Invalidate or implicitly by a newer generation, after which the next access
// drops and rebuilds it.
type resolveEntry struct {
	identity    resolveIdentity
	generation  uint64
	done        chan struct{}
	snapshot    Snapshot
	err         error
	invalidated bool
	elem        *list.Element
}

// Resolver resolves keys to snapshots with single-flight builds: concurrent
// Resolve calls for the same key run build exactly once and share the result,
// while different keys (including different TargetHash or RequestID) never
// interact.
//
// Resolver is safe for concurrent use. Entries are bounded by the configured
// limit with least-recently-used eviction. The caller owns the Resolver and
// must call Close to release the entry table; Close is idempotent, and
// in-flight builds and their waiters are unaffected by it.
type Resolver struct {
	mu      sync.Mutex
	limit   int
	entries map[resolveIdentity]*resolveEntry
	lru     *list.List // front is most recently used, elements are *resolveEntry
	closed  bool
}

// NewResolver creates a Resolver holding at most limit entries. A non-positive
// limit selects DefaultResolverLimit.
func NewResolver(limit int) *Resolver {
	if limit <= 0 {
		limit = DefaultResolverLimit
	}
	return &Resolver{
		limit:   limit,
		entries: make(map[resolveIdentity]*resolveEntry),
		lru:     list.New(),
	}
}

// Resolve returns the snapshot for key, building it at most once per
// generation. Concurrent callers for the same key share one build; a caller
// whose ctx is canceled while waiting stops waiting without affecting the
// build or other waiters. Build failures and panics are reported to all
// current waiters but never cached, so the next Resolve rebuilds.
func (r *Resolver) Resolve(ctx context.Context, key ResolveKey, build func(ctx context.Context) (Snapshot, error)) (Snapshot, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	identity := key.identity()

	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return Snapshot{}, ErrResolverClosed
	}
	if entry, ok := r.entries[identity]; ok && !entry.invalidated && entry.generation == key.Generation {
		r.lru.MoveToFront(entry.elem)
		r.mu.Unlock()
		return waitResolveEntry(ctx, entry)
	}

	// No usable entry: this caller becomes the single builder for the key.
	// A stale entry (invalidated or older generation) is replaced; its own
	// waiters keep their reference and still receive its result.
	entry := &resolveEntry{identity: identity, generation: key.Generation, done: make(chan struct{})}
	entry.elem = r.lru.PushFront(entry)
	r.entries[identity] = entry
	for len(r.entries) > r.limit {
		oldest := r.lru.Back()
		if oldest == nil {
			break
		}
		r.evictLocked(oldest.Value.(*resolveEntry))
	}
	r.mu.Unlock()

	return r.runBuild(ctx, entry, build)
}

// waitResolveEntry blocks until the entry's build completes or ctx is
// canceled. Canceling one waiter never affects the build or other waiters.
func waitResolveEntry(ctx context.Context, entry *resolveEntry) (Snapshot, error) {
	select {
	case <-entry.done:
		return entry.snapshot, entry.err
	case <-ctx.Done():
		return Snapshot{}, context.Cause(ctx)
	}
}

// runBuild executes the single build for entry, converts panics into
// ErrResolvePanic, releases every waiter, and drops failed entries instead of
// caching them.
func (r *Resolver) runBuild(ctx context.Context, entry *resolveEntry, build func(ctx context.Context) (Snapshot, error)) (snapshot Snapshot, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			snapshot = Snapshot{}
			err = fmt.Errorf("%w: %v", ErrResolvePanic, recovered)
		}

		r.mu.Lock()
		entry.snapshot = snapshot
		entry.err = err
		close(entry.done)
		if err != nil && !r.closed {
			// Failures are not cached; drop the entry only if it is still
			// the one registered for the identity.
			if current, ok := r.entries[entry.identity]; ok && current == entry {
				r.evictLocked(entry)
			}
		}
		r.mu.Unlock()
	}()

	return build(ctx)
}

// Invalidate marks the entry for key's identity invalidated so the next
// Resolve rebuilds it, even when the caller keeps the same generation.
// Invalidation never disturbs waiters already attached to the old entry.
func (r *Resolver) Invalidate(key ResolveKey) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return
	}
	if entry, ok := r.entries[key.identity()]; ok && entry.generation <= key.Generation {
		entry.invalidated = true
	}
}

// evictLocked removes entry from the LRU list and, if still registered, from
// the entry map. Callers must hold r.mu.
func (r *Resolver) evictLocked(entry *resolveEntry) {
	if entry.elem != nil {
		r.lru.Remove(entry.elem)
		entry.elem = nil
	}
	if current, ok := r.entries[entry.identity]; ok && current == entry {
		delete(r.entries, entry.identity)
	}
}

// Close releases the entry table. It is idempotent and safe for concurrent
// use; entries already built or building stay valid for their existing
// waiters, and Resolve calls after Close return ErrResolverClosed.
func (r *Resolver) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return
	}
	r.closed = true
	r.entries = make(map[resolveIdentity]*resolveEntry)
	r.lru.Init()
}
