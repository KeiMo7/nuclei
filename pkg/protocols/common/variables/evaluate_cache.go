package variables

import (
	"container/list"
	"crypto/sha256"
	"fmt"
	"sync"
)

// evaluateCacheCapacity bounds the shared evaluation cache. It is small on
// purpose: the cache only smooths repeated evaluation of the same template
// variables against an unchanged data layer, it is not a scan-wide store.
const evaluateCacheCapacity = 256

// evaluateCache is a small LRU cache from scope data digests to the
// TemplateValues produced by one evaluation. It stores template values only,
// never Interactsh URLs, because URL allocation is a side effect that must
// rerun whenever it is needed.
//
// The cache is safe for concurrent use. Stored and returned maps are copies,
// so callers own the maps they receive and cannot corrupt cached entries.
type evaluateCache struct {
	lock     sync.Mutex
	capacity int
	ll       *list.List // front is most recently used, elements are *evaluateCacheEntry
	items    map[string]*list.Element
}

// evaluateCacheEntry is one cached TemplateValues map under its digest key.
type evaluateCacheEntry struct {
	key            string
	templateValues map[string]interface{}
}

// newEvaluateCache creates an LRU cache holding at most capacity entries.
func newEvaluateCache(capacity int) *evaluateCache {
	if capacity <= 0 {
		capacity = evaluateCacheCapacity
	}
	return &evaluateCache{
		capacity: capacity,
		ll:       list.New(),
		items:    make(map[string]*list.Element),
	}
}

// get returns a copy of the cached TemplateValues for key and marks the entry
// most recently used.
func (c *evaluateCache) get(key string) (map[string]interface{}, bool) {
	c.lock.Lock()
	defer c.lock.Unlock()

	element, ok := c.items[key]
	if !ok {
		return nil, false
	}
	c.ll.MoveToFront(element)

	return copyTemplateValues(element.Value.(*evaluateCacheEntry).templateValues), true
}

// add stores a copy of templateValues under key, evicting the least recently
// used entries beyond capacity.
func (c *evaluateCache) add(key string, templateValues map[string]interface{}) {
	c.lock.Lock()
	defer c.lock.Unlock()

	if element, ok := c.items[key]; ok {
		c.ll.MoveToFront(element)
		element.Value.(*evaluateCacheEntry).templateValues = copyTemplateValues(templateValues)
		return
	}

	element := c.ll.PushFront(&evaluateCacheEntry{key: key, templateValues: copyTemplateValues(templateValues)})
	c.items[key] = element

	for len(c.items) > c.capacity {
		oldest := c.ll.Back()
		if oldest == nil {
			break
		}
		c.ll.Remove(oldest)
		delete(c.items, oldest.Value.(*evaluateCacheEntry).key)
	}
}

// clear drops all entries. It exists for tests that need a clean cache.
func (c *evaluateCache) clear() {
	c.lock.Lock()
	defer c.lock.Unlock()

	c.ll.Init()
	c.items = make(map[string]*list.Element)
}

// copyTemplateValues returns a shallow copy so cached maps are never aliased
// by callers.
func copyTemplateValues(values map[string]interface{}) map[string]interface{} {
	copied := make(map[string]interface{}, len(values))
	for key, value := range values {
		copied[key] = value
	}
	return copied
}

// sharedEvaluateCache is the process-wide evaluation cache used by
// EvaluateScope.
var sharedEvaluateCache = newEvaluateCache(evaluateCacheCapacity)

// makeEvaluateCacheKey builds the cache key for one EvaluateScope call. The
// key covers the template variable definitions, the full scope snapshot digest
// (data and template layers), and the options pointer so evaluations under
// different scan policies never share entries. Keys are deterministic for
// identical inputs.
func makeEvaluateCacheKey(variables *Variable, scope *Scope, snapshot Snapshot) string {
	variableDigest := digestVariableDefinitions(variables)
	snapshotDigest := snapshot.Digest()

	var optionsToken string
	if scope != nil && scope.options != nil {
		optionsToken = fmt.Sprintf("%p", scope.options)
	}

	return fmt.Sprintf("%x/%x/%s", variableDigest, snapshotDigest, optionsToken)
}

// digestVariableDefinitions hashes the variable definitions in insertion
// order so two different Variable sets never share a cache entry.
func digestVariableDefinitions(variables *Variable) [32]byte {
	hasher := sha256.New()
	variables.ForEach(func(key string, value interface{}) {
		writeDigestField(hasher, []byte(key))
		writeDigestValue(hasher, value)
	})

	var digest [32]byte
	copy(digest[:], hasher.Sum(nil))

	return digest
}
