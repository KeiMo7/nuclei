package variables

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tarunKoyalwar/goleak"
)

func testResolveSnapshot(seed string) Snapshot {
	return NewScope().AddDataValue("seed", seed).Snapshot()
}

func TestResolverDefaultLimit(t *testing.T) {
	resolver := NewResolver(0)
	t.Cleanup(resolver.Close)
	require.Equal(t, DefaultResolverLimit, resolver.limit)

	resolver = NewResolver(-5)
	t.Cleanup(resolver.Close)
	require.Equal(t, DefaultResolverLimit, resolver.limit)
}

func TestResolverConcurrentSameKeyBuildsOnce(t *testing.T) {
	resolver := NewResolver(16)
	t.Cleanup(resolver.Close)

	key := ResolveKey{TemplateID: "tpl", TargetHash: "target", RequestID: "req"}
	want := testResolveSnapshot("shared")

	var builds atomic.Int32
	build := func(ctx context.Context) (Snapshot, error) {
		builds.Add(1)
		time.Sleep(20 * time.Millisecond)
		return want, nil
	}

	const waiters = 10
	results := make(chan Snapshot, waiters)
	errs := make(chan error, waiters)
	var wg sync.WaitGroup
	for i := 0; i < waiters; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			snapshot, err := resolver.Resolve(context.Background(), key, build)
			if err != nil {
				errs <- err
				return
			}
			results <- snapshot
		}()
	}
	wg.Wait()
	close(results)
	close(errs)

	require.Empty(t, errs)
	require.Equal(t, int32(1), builds.Load(), "concurrent same-key resolves must build exactly once")
	for snapshot := range results {
		require.Equal(t, want.Digest(), snapshot.Digest(), "every waiter must share the built snapshot")
	}
}

func TestResolverDistinctKeysDoNotInteract(t *testing.T) {
	resolver := NewResolver(16)
	t.Cleanup(resolver.Close)

	base := ResolveKey{TemplateID: "tpl", TargetHash: "target", RequestID: "req"}
	var builds atomic.Int32
	build := func(ctx context.Context) (Snapshot, error) {
		builds.Add(1)
		return testResolveSnapshot("base"), nil
	}

	_, err := resolver.Resolve(context.Background(), base, build)
	require.NoError(t, err)
	require.Equal(t, int32(1), builds.Load())

	tests := []struct {
		name string
		key  ResolveKey
	}{
		{"other target", ResolveKey{TemplateID: "tpl", TargetHash: "other-target", RequestID: "req"}},
		{"other request", ResolveKey{TemplateID: "tpl", TargetHash: "target", RequestID: "other-req"}},
		{"other template", ResolveKey{TemplateID: "other-tpl", TargetHash: "target", RequestID: "req"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			before := builds.Load()
			_, err := resolver.Resolve(context.Background(), test.key, build)
			require.NoError(t, err)
			require.Equal(t, before+1, builds.Load(), "a different identity must build independently")
		})
	}

	// The original key is still cached and must not rebuild.
	_, err = resolver.Resolve(context.Background(), base, build)
	require.NoError(t, err)
	require.Equal(t, int32(1)+int32(len(tests)), builds.Load())
}

func TestResolverInvalidateAndGeneration(t *testing.T) {
	resolver := NewResolver(16)
	t.Cleanup(resolver.Close)

	key := ResolveKey{TemplateID: "tpl", TargetHash: "target", RequestID: "req"}
	var builds atomic.Int32
	build := func(ctx context.Context) (Snapshot, error) {
		builds.Add(1)
		return testResolveSnapshot("gen"), nil
	}

	_, err := resolver.Resolve(context.Background(), key, build)
	require.NoError(t, err)
	_, err = resolver.Resolve(context.Background(), key, build)
	require.NoError(t, err)
	require.Equal(t, int32(1), builds.Load(), "same key and generation must reuse the entry")

	resolver.Invalidate(key)
	_, err = resolver.Resolve(context.Background(), key, build)
	require.NoError(t, err)
	require.Equal(t, int32(2), builds.Load(), "invalidated entries must rebuild on next access")

	nextGeneration := key
	nextGeneration.Generation = 1
	_, err = resolver.Resolve(context.Background(), nextGeneration, build)
	require.NoError(t, err)
	require.Equal(t, int32(3), builds.Load(), "a bumped generation must rebuild")
}

func TestResolverWaiterCancellationDoesNotAffectOthers(t *testing.T) {
	defer goleak.VerifyNone(t)

	resolver := NewResolver(16)
	t.Cleanup(resolver.Close)

	key := ResolveKey{TemplateID: "tpl", TargetHash: "target", RequestID: "req"}
	want := testResolveSnapshot("cancel-safe")

	started := make(chan struct{})
	release := make(chan struct{})
	var builds atomic.Int32
	build := func(ctx context.Context) (Snapshot, error) {
		builds.Add(1)
		close(started)
		<-release
		return want, nil
	}

	// The first caller becomes the builder and blocks inside build.
	builderResult := make(chan error, 1)
	go func() {
		_, err := resolver.Resolve(context.Background(), key, build)
		builderResult <- err
	}()
	<-started

	// A second caller waits on the same entry and is canceled mid-wait.
	waiterCtx, cancelWaiter := context.WithCancel(context.Background())
	waiterResult := make(chan error, 1)
	go func() {
		_, err := resolver.Resolve(waiterCtx, key, build)
		waiterResult <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancelWaiter()
	require.ErrorIs(t, <-waiterResult, context.Canceled)

	// Releasing the build must still deliver the result to the builder, and
	// the entry must be cached for later callers.
	close(release)
	require.NoError(t, <-builderResult)
	require.Equal(t, int32(1), builds.Load())

	snapshot, err := resolver.Resolve(context.Background(), key, build)
	require.NoError(t, err)
	require.Equal(t, want.Digest(), snapshot.Digest())
	require.Equal(t, int32(1), builds.Load(), "canceling one waiter must not disturb the build or other waiters")
}

func TestResolverBuildErrorIsNotCached(t *testing.T) {
	resolver := NewResolver(16)
	t.Cleanup(resolver.Close)

	key := ResolveKey{TemplateID: "tpl", TargetHash: "target", RequestID: "req"}
	errBuild := errors.New("render failed")

	var builds atomic.Int32
	build := func(ctx context.Context) (Snapshot, error) {
		if builds.Add(1) == 1 {
			return Snapshot{}, errBuild
		}
		return testResolveSnapshot("recovered"), nil
	}

	_, err := resolver.Resolve(context.Background(), key, build)
	require.ErrorIs(t, err, errBuild)

	snapshot, err := resolver.Resolve(context.Background(), key, build)
	require.NoError(t, err, "a failed build must not be cached; the next call rebuilds")
	require.Equal(t, testResolveSnapshot("recovered").Digest(), snapshot.Digest())
	require.Equal(t, int32(2), builds.Load())
}

func TestResolverBuildPanicBecomesError(t *testing.T) {
	resolver := NewResolver(16)
	t.Cleanup(resolver.Close)

	key := ResolveKey{TemplateID: "tpl", TargetHash: "target", RequestID: "req"}
	var builds atomic.Int32
	build := func(ctx context.Context) (Snapshot, error) {
		if builds.Add(1) == 1 {
			panic("boom")
		}
		return testResolveSnapshot("after-panic"), nil
	}

	_, err := resolver.Resolve(context.Background(), key, build)
	require.ErrorIs(t, err, ErrResolvePanic, "a panicking build must surface as ErrResolvePanic, not crash the process")

	snapshot, err := resolver.Resolve(context.Background(), key, build)
	require.NoError(t, err, "panics must not be cached; the next call rebuilds")
	require.Equal(t, testResolveSnapshot("after-panic").Digest(), snapshot.Digest())
	require.Equal(t, int32(2), builds.Load())
}

func TestResolverEvictsLeastRecentlyUsed(t *testing.T) {
	resolver := NewResolver(2)
	t.Cleanup(resolver.Close)

	keyFor := func(id string) ResolveKey {
		return ResolveKey{TemplateID: "tpl", TargetHash: id, RequestID: "req"}
	}
	buildCounts := map[string]*atomic.Int32{
		"a": {}, "b": {}, "c": {},
	}
	buildFor := func(id string) func(ctx context.Context) (Snapshot, error) {
		return func(ctx context.Context) (Snapshot, error) {
			buildCounts[id].Add(1)
			return testResolveSnapshot(id), nil
		}
	}

	_, err := resolver.Resolve(context.Background(), keyFor("a"), buildFor("a"))
	require.NoError(t, err)
	_, err = resolver.Resolve(context.Background(), keyFor("b"), buildFor("b"))
	require.NoError(t, err)

	// Touch "a" so "b" becomes the least recently used entry.
	_, err = resolver.Resolve(context.Background(), keyFor("a"), buildFor("a"))
	require.NoError(t, err)

	_, err = resolver.Resolve(context.Background(), keyFor("c"), buildFor("c"))
	require.NoError(t, err)
	require.Equal(t, int32(1), buildCounts["c"].Load())

	// "b" was the least recently used entry and must have been evicted.
	_, err = resolver.Resolve(context.Background(), keyFor("b"), buildFor("b"))
	require.NoError(t, err)
	require.Equal(t, int32(2), buildCounts["b"].Load(), "the least recently used entry must be evicted")

	// Re-adding "b" evicted "a" (the new least recently used), while "c"
	// survived because "b"'s rebuild did not touch it.
	_, err = resolver.Resolve(context.Background(), keyFor("c"), buildFor("c"))
	require.NoError(t, err)
	require.Equal(t, int32(1), buildCounts["c"].Load(), "recently built entries must survive eviction")
	_, err = resolver.Resolve(context.Background(), keyFor("a"), buildFor("a"))
	require.NoError(t, err)
	require.Equal(t, int32(2), buildCounts["a"].Load())
}

func TestResolverCloseIsIdempotent(t *testing.T) {
	defer goleak.VerifyNone(t)

	resolver := NewResolver(4)
	key := ResolveKey{TemplateID: "tpl", TargetHash: "target", RequestID: "req"}
	_, err := resolver.Resolve(context.Background(), key, func(ctx context.Context) (Snapshot, error) {
		return testResolveSnapshot("pre-close"), nil
	})
	require.NoError(t, err)

	resolver.Close()
	resolver.Close()

	_, err = resolver.Resolve(context.Background(), key, func(ctx context.Context) (Snapshot, error) {
		return testResolveSnapshot("post-close"), nil
	})
	require.ErrorIs(t, err, ErrResolverClosed)

	// Invalidate after Close is a no-op and must not panic.
	resolver.Invalidate(key)
}

func BenchmarkResolverHit(b *testing.B) {
	resolver := NewResolver(16)
	b.Cleanup(resolver.Close)

	key := ResolveKey{TemplateID: "tpl", TargetHash: "target", RequestID: "req"}
	snapshot := testResolveSnapshot("bench")
	_, err := resolver.Resolve(context.Background(), key, func(ctx context.Context) (Snapshot, error) {
		return snapshot, nil
	})
	require.NoError(b, err)

	build := func(ctx context.Context) (Snapshot, error) {
		b.Fatal("build must not run on a cache hit")
		return Snapshot{}, nil
	}

	b.ReportAllocs()
	for b.Loop() {
		if _, err := resolver.Resolve(context.Background(), key, build); err != nil {
			b.Fatal(err)
		}
	}
}
