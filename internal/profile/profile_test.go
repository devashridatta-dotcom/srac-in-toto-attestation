package profile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestGeneratedConformanceSuite(t *testing.T) {
	root := t.TempDir()
	fixtures := filepath.Join(root, "fixtures")
	policy := filepath.Join(root, "policy.json")
	if err := GenerateDemo(fixtures, policy); err != nil {
		t.Fatal(err)
	}
	results, err := VerifySuite(fixtures, policy)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 5 {
		t.Fatalf("got %d fixtures, want 5", len(results))
	}
	eligible := 0
	for _, result := range results {
		if result.SafetyClaimTruth != "not-evaluated" {
			t.Fatalf("fixture %s inferred safety truth", result.Fixture)
		}
		if result.PolicyEligible {
			eligible++
		}
	}
	if eligible != 2 {
		t.Fatalf("got %d eligible fixtures, want 2", eligible)
	}
}

func TestFixtureGenerationIsDeterministic(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "first")
	second := filepath.Join(root, "second")
	if err := GenerateDemo(filepath.Join(first, "fixtures"), filepath.Join(first, "policy.json")); err != nil {
		t.Fatal(err)
	}
	if err := GenerateDemo(filepath.Join(second, "fixtures"), filepath.Join(second, "policy.json")); err != nil {
		t.Fatal(err)
	}
	compareFiles(t, filepath.Join(first, "policy.json"), filepath.Join(second, "policy.json"))
	compareFiles(t,
		filepath.Join(first, "fixtures", "positive-complete-authorized", "envelope.dsse.json"),
		filepath.Join(second, "fixtures", "positive-complete-authorized", "envelope.dsse.json"),
	)
}

func TestSchemasAreValidJSON(t *testing.T) {
	paths := []string{
		filepath.Join("..", "..", "schema", "safety-evidence-predicate-v0.1.schema.json"),
		filepath.Join("..", "..", "schema", "safety-evidence-graph-v0.1.schema.json"),
	}
	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var value any
		if err := json.Unmarshal(content, &value); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
	}
}

func compareFiles(t *testing.T, first, second string) {
	t.Helper()
	left, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	right, err := os.ReadFile(second)
	if err != nil {
		t.Fatal(err)
	}
	if string(left) != string(right) {
		t.Fatalf("generated files differ: %s and %s", first, second)
	}
}
