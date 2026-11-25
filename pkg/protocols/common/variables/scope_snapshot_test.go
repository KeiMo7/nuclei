package variables

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestScopeSnapshotCapturesValuesAndKinds(t *testing.T) {
	tests := []struct {
		name     string
		build    func() *Scope
		key      string
		wantKind ScopeValueKind
		wantVal  interface{}
	}{
		{
			name: "data value",
			build: func() *Scope {
				return NewScope().AddDataValue("host", "example.com")
			},
			key:      "host",
			wantKind: ScopeValueData,
			wantVal:  "example.com",
		},
		{
			name: "template value",
			build: func() *Scope {
				return NewScope().AddTemplateValue("derived", "{{host}}")
			},
			key:      "derived",
			wantKind: ScopeValueTemplate,
			wantVal:  "{{host}}",
		},
		{
			name: "slice value",
			build: func() *Scope {
				return NewScope().AddDataValue("list", []interface{}{"a", "b"})
			},
			key:      "list",
			wantKind: ScopeValueData,
			wantVal:  []interface{}{"a", "b"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := test.build().Snapshot()

			value, ok := snapshot.Get(test.key)
			require.True(t, ok)
			require.Equal(t, test.wantVal, value)

			kind, ok := snapshot.Kind(test.key)
			require.True(t, ok)
			require.Equal(t, test.wantKind, kind)
		})
	}
}

func TestScopeSnapshotEmptySources(t *testing.T) {
	t.Run("nil scope", func(t *testing.T) {
		var scope *Scope
		snapshot := scope.Snapshot()

		_, ok := snapshot.Get("missing")
		require.False(t, ok)
		_, ok = snapshot.Kind("missing")
		require.False(t, ok)
		require.Empty(t, snapshot.Values())
	})

	t.Run("zero snapshot", func(t *testing.T) {
		var snapshot Snapshot

		_, ok := snapshot.Get("missing")
		require.False(t, ok)
		_, ok = snapshot.Kind("missing")
		require.False(t, ok)

		values := snapshot.Values()
		require.NotNil(t, values, "Values must return a fresh map even for the zero snapshot")
		require.Empty(t, values)
	})
}

func TestSnapshotValuesReturnsFreshMap(t *testing.T) {
	snapshot := NewScope().AddDataValue("key", "value").Snapshot()

	values := snapshot.Values()
	values["key"] = "mutated"
	values["injected"] = "new"

	got, ok := snapshot.Get("key")
	require.True(t, ok)
	require.Equal(t, "value", got, "mutating the returned map must not affect the snapshot")

	_, ok = snapshot.Get("injected")
	require.False(t, ok)

	fresh := snapshot.Values()
	fresh["key"] = "changed-elsewhere"
	require.Equal(t, "mutated", values["key"], "every Values call must return an independent map")
}

func TestSnapshotImmutableAfterScopeMutation(t *testing.T) {
	scope := NewScope().AddDataValue("key", "before")
	snapshot := scope.Snapshot()

	scope.AddDataValue("key", "after")
	scope.AddDataValue("extra", "new")

	got, ok := snapshot.Get("key")
	require.True(t, ok)
	require.Equal(t, "before", got)

	_, ok = snapshot.Get("extra")
	require.False(t, ok)
}

func TestSnapshotDoesNotHoldCallerMap(t *testing.T) {
	caller := map[string]interface{}{"key": "value"}
	scope := NewScope().AddData(caller)
	snapshot := scope.Snapshot()

	caller["key"] = "mutated"
	caller["extra"] = "new"

	got, ok := snapshot.Get("key")
	require.True(t, ok)
	require.Equal(t, "value", got, "the snapshot must not reference the caller's map")

	_, ok = snapshot.Get("extra")
	require.False(t, ok)
}

func TestSnapshotDigestDeterministic(t *testing.T) {
	scope := NewScope().
		AddData(map[string]interface{}{"zeta": 1, "alpha": "two", "mid": true}).
		AddTemplateValue("derived", "{{alpha}}")

	want := scope.Snapshot().Digest()
	for i := 0; i < 1000; i++ {
		require.Equal(t, want, scope.Snapshot().Digest(), "digest must be identical on every call")
	}
}

func TestSnapshotDigestEmptyIsFixed(t *testing.T) {
	empty := sha256.Sum256(nil)

	require.Equal(t, empty, Snapshot{}.Digest())
	require.Equal(t, empty, NewScope().Snapshot().Digest())

	var scope *Scope
	require.Equal(t, empty, scope.Snapshot().Digest())
}

func TestSnapshotDigestIgnoresInsertionOrder(t *testing.T) {
	first := NewScope().AddDataValue("a", "1").AddDataValue("b", "2").Snapshot()
	second := NewScope().AddDataValue("b", "2").AddDataValue("a", "1").Snapshot()

	require.Equal(t, first.Digest(), second.Digest(), "digest must not depend on map insertion or iteration order")
}

func TestSnapshotDigestChanges(t *testing.T) {
	base := NewScope().AddDataValue("key", "value").Snapshot()

	tests := []struct {
		name     string
		snapshot Snapshot
	}{
		{"value change", NewScope().AddDataValue("key", "other").Snapshot()},
		{"kind change", NewScope().AddTemplateValue("key", "value").Snapshot()},
		{"key change", NewScope().AddDataValue("other", "value").Snapshot()},
		{"type change", NewScope().AddDataValue("key", 1).Snapshot()},
		{"extra key", NewScope().AddDataValue("key", "value").AddDataValue("extra", "x").Snapshot()},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.NotEqual(t, base.Digest(), test.snapshot.Digest())
		})
	}
}
