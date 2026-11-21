package core

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/isolation"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func crashTemplate(id string) *templates.Template {
	return &templates.Template{ID: id, Executer: &panicExecuter{}}
}

func metaInput(target string) *contextargs.MetaInput {
	return &contextargs.MetaInput{Input: target}
}

func TestTwoRunsProduceTheSameIsolationList(t *testing.T) {
	run := func() isolation.Summary {
		engine := New(&types.Options{})
		recorder := isolation.NewRecorder(isolation.Threshold{Retry: 0, SignatureFailures: 2})
		engine.SetIsolationRecorder(recorder)

		// the same crashing template on two targets: the decision times differ,
		// the list must not
		for _, target := range []string{"https://b.test", "https://a.test"} {
			_, _ = engine.runUnit(context.Background(), crashTemplate("crashy"), metaInput(target))
		}
		return isolation.NewSummary(recorder, time.Time{}, time.Time{})
	}

	first, second := run(), run()
	// the unit list carries the same decisions; only the wall clock differs
	normalize := func(summary isolation.Summary) isolation.Summary {
		for i := range summary.Units {
			summary.Units[i].LastAt = time.Time{}
		}
		for i := range summary.Isolated {
			summary.Isolated[i].LastAt = time.Time{}
		}
		for i := range summary.Decisions {
			summary.Decisions[i].At = time.Time{}
		}
		return summary
	}
	require.Equal(t, normalize(first), normalize(second), "two identical runs produce the same list")

	var listA, listB bytes.Buffer
	require.NoError(t, first.WriteReadable(&listA))
	require.NoError(t, second.WriteReadable(&listB))
	require.Equal(t, listA.String(), listB.String())

	// the machine-readable summary carries the same decision classes in the
	// same order, independent of the order decisions were recorded in
	firstJSON, err := json.Marshal(first)
	require.NoError(t, err)
	secondJSON, err := json.Marshal(second)
	require.NoError(t, err)
	var decodedFirst, decodedSecond struct {
		Units []struct {
			Unit     string   `json:"unit"`
			Reason   string   `json:"reason"`
			Targets  []string `json:"targets"`
			Affected int      `json:"affected"`
		} `json:"units"`
		Isolated []struct {
			Unit string `json:"unit"`
		} `json:"isolated"`
		Decisions []struct {
			Unit    string `json:"unit"`
			Reason  string `json:"reason"`
			Outcome string `json:"outcome"`
			Attempt int    `json:"attempt"`
		} `json:"decisions"`
	}
	require.NoError(t, json.Unmarshal(firstJSON, &decodedFirst))
	require.NoError(t, json.Unmarshal(secondJSON, &decodedSecond))
	require.Equal(t, decodedFirst.Units, decodedSecond.Units)
	require.Equal(t, decodedFirst.Isolated, decodedSecond.Isolated)
	require.Equal(t, decodedFirst.Decisions, decodedSecond.Decisions)
}
