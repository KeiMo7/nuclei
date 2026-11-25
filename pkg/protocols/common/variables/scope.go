package variables

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
	"reflect"
	"sort"

	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

// Scope contains values used while evaluating template variables.
//
// Data values are terminal values from runtime, options, constants, payloads,
// or protocol context. Template values are produced from the template variables
// section and may be re-rendered when later data becomes available.
//
// A Scope is not safe for concurrent mutation; callers must serialize Add*
// calls against reads such as Values and Snapshot.
type Scope struct {
	values  map[string]scopeValue
	options *types.Options
}

// ScopeValueKind identifies the source layer of a value held by a Scope.
type ScopeValueKind uint8

const (
	// ScopeValueData marks terminal data values from runtime, options,
	// constants, payloads, or protocol context.
	ScopeValueData ScopeValueKind = iota
	// ScopeValueTemplate marks values produced from the template variables
	// section.
	ScopeValueTemplate
)

type scopeValue struct {
	value interface{}
	kind  ScopeValueKind
}

// NewScope creates an empty variable evaluation scope.
func NewScope() *Scope {
	return &Scope{values: make(map[string]scopeValue)}
}

// WithOptions binds this scope to the current scan without adding template variables.
func (s *Scope) WithOptions(options *types.Options) *Scope {
	s.options = options
	return s
}

// AddData adds terminal data values to the scope.
func (s *Scope) AddData(values ...map[string]interface{}) *Scope {
	if s == nil {
		return s
	}

	for _, valueMap := range values {
		for key, value := range valueMap {
			s.AddDataValue(key, value)
		}
	}

	return s
}

// AddDataValue adds one terminal data value to the scope.
func (s *Scope) AddDataValue(key string, value interface{}) *Scope {
	if s == nil {
		return s
	}

	s.values[key] = scopeValue{value: value, kind: ScopeValueData}

	return s
}

// AddTemplate adds values produced from template variables.
func (s *Scope) AddTemplate(values map[string]interface{}) *Scope {
	if s == nil {
		return s
	}

	for key, value := range values {
		s.AddTemplateValue(key, value)
	}

	return s
}

// AddTemplateValue adds one value produced from template variables.
func (s *Scope) AddTemplateValue(key string, value interface{}) *Scope {
	if s == nil {
		return s
	}

	s.values[key] = scopeValue{value: value, kind: ScopeValueTemplate}

	return s
}

// Values returns a plain value map for render evaluation.
func (s *Scope) Values() map[string]interface{} {
	if s == nil || len(s.values) == 0 {
		return nil
	}

	values := make(map[string]interface{}, len(s.values))
	for key, value := range s.values {
		values[key] = value.value
	}

	return values
}

func (s *Scope) clone() *Scope {
	if s == nil {
		return NewScope()
	}

	clone := NewScope().WithOptions(s.options)
	for key, value := range s.values {
		clone.values[key] = value
	}

	return clone
}

func (s *Scope) get(key string) (scopeValue, bool) {
	if s == nil {
		return scopeValue{}, false
	}

	value, ok := s.values[key]

	return value, ok
}

// Snapshot is an immutable view of a Scope's values and their source kinds.
//
// The snapshot copies the scope's entries at creation time: later mutations of
// the scope, and mutations of maps returned by Values, never leak back into
// the snapshot. A Snapshot holds no reference to any caller-provided map. The
// zero Snapshot is valid and behaves as an empty snapshot. All methods are
// safe for concurrent use because a Snapshot is never mutated after creation.
type Snapshot struct {
	entries map[string]snapshotEntry
}

// snapshotEntry is one immutable value plus the layer it came from.
type snapshotEntry struct {
	value interface{}
	kind  ScopeValueKind
}

// Snapshot returns an immutable copy of the scope's current values and their
// source kinds. A nil scope yields an empty snapshot.
func (s *Scope) Snapshot() Snapshot {
	if s == nil || len(s.values) == 0 {
		return Snapshot{}
	}

	entries := make(map[string]snapshotEntry, len(s.values))
	for key, value := range s.values {
		entries[key] = snapshotEntry{value: value.value, kind: value.kind}
	}

	return Snapshot{entries: entries}
}

// Get returns the value for key and whether the snapshot contains it.
func (v Snapshot) Get(key string) (interface{}, bool) {
	entry, ok := v.entries[key]
	if !ok {
		return nil, false
	}

	return entry.value, true
}

// Values returns a fresh map of the snapshot's values on every call; callers
// may mutate the returned map without affecting the snapshot.
func (v Snapshot) Values() map[string]interface{} {
	values := make(map[string]interface{}, len(v.entries))
	for key, entry := range v.entries {
		values[key] = entry.value
	}

	return values
}

// Kind returns the source kind of key and whether the snapshot contains it.
func (v Snapshot) Kind(key string) (ScopeValueKind, bool) {
	entry, ok := v.entries[key]
	if !ok {
		return 0, false
	}

	return entry.kind, true
}

// Digest returns a deterministic SHA-256 digest of the snapshot. Keys are
// sorted before hashing, and for each key the digest covers the key, its
// source kind, the value's type name, and the value itself. The digest never
// mixes in timestamps, randomness, or pointer addresses, so identical inputs
// always produce identical digests; the empty snapshot has one fixed digest.
func (v Snapshot) Digest() [32]byte {
	keys := make([]string, 0, len(v.entries))
	for key := range v.entries {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	hasher := sha256.New()
	for _, key := range keys {
		entry := v.entries[key]
		writeDigestField(hasher, []byte(key))
		hasher.Write([]byte{byte(entry.kind)})
		writeDigestValue(hasher, entry.value)
	}

	var digest [32]byte
	copy(digest[:], hasher.Sum(nil))

	return digest
}

// writeDigestField writes one length-prefixed byte field so concatenated
// fields cannot alias each other.
func writeDigestField(hasher hash.Hash, data []byte) {
	var length [8]byte
	binary.LittleEndian.PutUint64(length[:], uint64(len(data)))
	_, _ = hasher.Write(length[:])
	_, _ = hasher.Write(data)
}

// writeDigestValue writes a value's type name followed by a deterministic
// encoding of the value itself.
func writeDigestValue(hasher hash.Hash, value interface{}) {
	if value == nil {
		writeDigestField(hasher, nil)
		writeDigestField(hasher, []byte("<nil>"))
		return
	}

	reflected := reflect.ValueOf(value)
	writeDigestField(hasher, []byte(reflected.Type().String()))
	writeDigestReflect(hasher, reflected)
}

// writeDigestReflect encodes reflected values deterministically: numbers and
// strings in binary, slices and arrays in order, maps sorted by key, and
// pointers and interfaces by their target so addresses never leak in.
func writeDigestReflect(hasher hash.Hash, value reflect.Value) {
	var buf [8]byte

	switch value.Kind() {
	case reflect.String:
		writeDigestField(hasher, []byte(value.String()))
	case reflect.Bool:
		if value.Bool() {
			_, _ = hasher.Write([]byte{1})
		} else {
			_, _ = hasher.Write([]byte{0})
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		binary.LittleEndian.PutUint64(buf[:], uint64(value.Int()))
		_, _ = hasher.Write(buf[:])
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		binary.LittleEndian.PutUint64(buf[:], value.Uint())
		_, _ = hasher.Write(buf[:])
	case reflect.Float32, reflect.Float64:
		binary.LittleEndian.PutUint64(buf[:], math.Float64bits(value.Float()))
		_, _ = hasher.Write(buf[:])
	case reflect.Slice:
		if value.Type().Elem().Kind() == reflect.Uint8 {
			writeDigestField(hasher, value.Bytes())
			return
		}
		writeDigestSequence(hasher, value)
	case reflect.Array:
		writeDigestSequence(hasher, value)
	case reflect.Map:
		keys := value.MapKeys()
		sort.Slice(keys, func(i, j int) bool {
			return fmt.Sprint(keys[i].Interface()) < fmt.Sprint(keys[j].Interface())
		})
		binary.LittleEndian.PutUint64(buf[:], uint64(len(keys)))
		_, _ = hasher.Write(buf[:])
		for _, key := range keys {
			writeDigestReflect(hasher, key)
			writeDigestReflect(hasher, value.MapIndex(key))
		}
	case reflect.Pointer, reflect.Interface:
		if value.IsNil() {
			writeDigestField(hasher, []byte("<nil>"))
			return
		}
		writeDigestReflect(hasher, value.Elem())
	default:
		// Structs and other kinds print deterministically with fmt (map keys
		// are sorted by the fmt package), which is sufficient for the rare
		// non-scalar values that reach a scope.
		writeDigestField(hasher, []byte(fmt.Sprintf("%v", value.Interface())))
	}
}

// writeDigestReflect writes a length-prefixed sequence of elements in order.
func writeDigestSequence(hasher hash.Hash, value reflect.Value) {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], uint64(value.Len()))
	_, _ = hasher.Write(buf[:])
	for i := 0; i < value.Len(); i++ {
		writeDigestReflect(hasher, value.Index(i))
	}
}
