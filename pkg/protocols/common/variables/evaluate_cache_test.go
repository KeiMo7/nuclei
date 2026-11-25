package variables

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/utils"
	"github.com/stretchr/testify/require"
)

func TestEvaluateCacheEvictsLeastRecentlyUsed(t *testing.T) {
	cache := newEvaluateCache(2)

	cache.add("a", map[string]interface{}{"v": "a"})
	cache.add("b", map[string]interface{}{"v": "b"})

	// Touch "a" so "b" becomes the eviction candidate.
	_, ok := cache.get("a")
	require.True(t, ok)

	cache.add("c", map[string]interface{}{"v": "c"})

	_, ok = cache.get("b")
	require.False(t, ok, "the least recently used entry must be evicted")
	_, ok = cache.get("a")
	require.True(t, ok)
	_, ok = cache.get("c")
	require.True(t, ok)
}

func TestEvaluateCacheHonoursCapacity(t *testing.T) {
	cache := newEvaluateCache(evaluateCacheCapacity)

	for i := 0; i < evaluateCacheCapacity*4; i++ {
		cache.add(string(rune('a'+i%26))+string(rune('0'+i/26)), map[string]interface{}{"i": i})
	}

	cache.lock.Lock()
	size := len(cache.items)
	cache.lock.Unlock()
	require.Equal(t, evaluateCacheCapacity, size, "the cache must never grow beyond its capacity")
}

func TestEvaluateCacheStoresCopies(t *testing.T) {
	cache := newEvaluateCache(4)

	stored := map[string]interface{}{"key": "original"}
	cache.add("k", stored)
	stored["key"] = "mutated"
	stored["extra"] = "injected"

	got, ok := cache.get("k")
	require.True(t, ok)
	require.Equal(t, map[string]interface{}{"key": "original"}, got, "mutating the caller's map must not affect the cache")

	got["key"] = "mutated-again"
	again, ok := cache.get("k")
	require.True(t, ok)
	require.Equal(t, "original", again["key"], "mutating a returned map must not affect the cache")
}

func TestEvaluateScopeReusesTemplateValuesWhenDataUnchanged(t *testing.T) {
	sharedEvaluateCache.clear()

	var calls int
	withVariableTestHelperFunction(t, "cachetest_count", func(args ...interface{}) (interface{}, error) {
		calls++
		return "counted", nil
	})

	variables := &Variable{
		LazyEval:                  true,
		InsertionOrderedStringMap: *utils.NewEmptyInsertionOrderedStringMap(1),
	}
	variables.Set("cachetest_token", "{{cachetest_count()}}")

	scope := NewScope().AddData(map[string]interface{}{"Host": "cachetest.example"})

	first := variables.EvaluateScope(scope)
	require.False(t, first.Reused)
	require.Equal(t, 1, calls)
	require.Equal(t, "counted", first.Values["cachetest_token"])
	require.Equal(t, "counted", first.TemplateValues["cachetest_token"])

	second := variables.EvaluateScope(scope)
	require.True(t, second.Reused, "an unchanged data digest must reuse the cached template values")
	require.Equal(t, 1, calls, "the helper must not run again on reuse")
	require.Equal(t, first.Values, second.Values)
	require.Equal(t, first.TemplateValues, second.TemplateValues)
}

func TestEvaluateScopeRecomputesWhenDataChanges(t *testing.T) {
	sharedEvaluateCache.clear()

	var calls int
	withVariableTestHelperFunction(t, "cachetest_recount", func(args ...interface{}) (interface{}, error) {
		calls++
		return "recounted", nil
	})

	variables := &Variable{
		LazyEval:                  true,
		InsertionOrderedStringMap: *utils.NewEmptyInsertionOrderedStringMap(1),
	}
	variables.Set("cachetest_token", "{{cachetest_recount()}}")

	scope := NewScope().AddData(map[string]interface{}{"Host": "cachetest.example"})
	first := variables.EvaluateScope(scope)
	require.False(t, first.Reused)
	require.Equal(t, 1, calls)

	changed := variables.EvaluateScope(NewScope().AddData(map[string]interface{}{
		"Host":  "cachetest.example",
		"Extra": "new-data",
	}))
	require.False(t, changed.Reused, "a changed data digest must recompute")
	require.Equal(t, 2, calls)
	require.Equal(t, "recounted", changed.Values["cachetest_token"])

	// The first scope's digest is still cached and hits again.
	reused := variables.EvaluateScope(scope)
	require.True(t, reused.Reused)
	require.Equal(t, 2, calls)
}

func TestEvaluateScopeDataOverrideWinsOnReuse(t *testing.T) {
	sharedEvaluateCache.clear()

	variables := &Variable{
		LazyEval:                  true,
		InsertionOrderedStringMap: *utils.NewEmptyInsertionOrderedStringMap(1),
	}
	variables.Set("cachetest_token", "declared")

	scope := NewScope().AddData(map[string]interface{}{"cachetest_token": "server-issued"})
	first := variables.EvaluateScope(scope)
	require.Equal(t, "server-issued", first.Values["cachetest_token"])
	require.NotContains(t, first.TemplateValues, "cachetest_token")

	second := variables.EvaluateScope(scope)
	require.True(t, second.Reused)
	require.Equal(t, "server-issued", second.Values["cachetest_token"], "data overrides must win on the reused path too")
	require.NotContains(t, second.TemplateValues, "cachetest_token")
}

func TestEvaluateScopeDoesNotModifyScope(t *testing.T) {
	sharedEvaluateCache.clear()

	variables := &Variable{
		LazyEval:                  true,
		InsertionOrderedStringMap: *utils.NewEmptyInsertionOrderedStringMap(2),
	}
	variables.Set("cachetest_a", "hello")
	variables.Set("cachetest_b", "{{cachetest_a}} world")

	scope := NewScope().AddData(map[string]interface{}{"Host": "cachetest.example"})
	before := scope.Snapshot()

	evaluation := variables.EvaluateScope(scope)
	require.Equal(t, "hello world", evaluation.Values["cachetest_b"])

	after := scope.Snapshot()
	require.Equal(t, before.Digest(), after.Digest(), "EvaluateScope must not modify the passed scope")
	require.Equal(t, before.Values(), after.Values())

	// The reused path must not modify the scope either.
	reused := variables.EvaluateScope(scope)
	require.True(t, reused.Reused)
	require.Equal(t, before.Digest(), scope.Snapshot().Digest())
}
