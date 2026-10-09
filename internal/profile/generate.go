package profile

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const (
	authorizedKeyID   = "demo-safety-authority-ed25519"
	unauthorizedKeyID = "demo-untrusted-reviewer-ed25519"
	authorizedID      = "https://example.org/authorities/safety-board"
	unauthorizedID    = "https://example.org/identities/untrusted-reviewer"
)

type fixtureDefinition struct {
	name             string
	graph            SafetyEvidenceGraph
	statementSubject Subject
	keyID            string
	privateKey       ed25519.PrivateKey
	authorityID      string
	expected         ExpectedResult
}

func GenerateDemo(fixturesDir, policyPath string) error {
	authorizedPrivate := fixturePrivateKey("srac-demo-authorized-key-v1")
	unauthorizedPrivate := fixturePrivateKey("srac-demo-unauthorized-key-v1")
	policy := Policy{
		VerificationKeys: []VerificationKey{
			verificationKey(authorizedKeyID, authorizedPrivate.Public().(ed25519.PublicKey)),
			verificationKey(unauthorizedKeyID, unauthorizedPrivate.Public().(ed25519.PublicKey)),
		},
		AuthorizedSigners: []AuthorizedSigner{{
			KeyID:       authorizedKeyID,
			AuthorityID: authorizedID,
		}},
		AllowNoActionWithoutEvidence: true,
	}
	if err := writeJSON(policyPath, policy); err != nil {
		return err
	}

	productSubject := fixtureSubject("pkg:example/safety-controller@1.0.0", "product-a")
	substitutedSubject := fixtureSubject("pkg:example/infotainment-controller@1.0.0", "product-b")
	complete := completeGraph(productSubject)
	missingEvidence := completeGraph(productSubject)
	missingEvidence.Evidence = []Evidence{}
	noAction := noActionGraph(productSubject)

	definitions := []fixtureDefinition{
		{
			name:             "positive-complete-authorized",
			graph:            complete,
			statementSubject: productSubject,
			keyID:            authorizedKeyID,
			privateKey:       authorizedPrivate,
			authorityID:      authorizedID,
			expected: ExpectedResult{
				Signature: "pass", ArtifactBinding: "pass", GraphCompleteness: "pass", Authorization: "pass", PolicyEligible: true,
			},
		},
		{
			name:             "negative-incomplete-missing-evidence",
			graph:            missingEvidence,
			statementSubject: productSubject,
			keyID:            authorizedKeyID,
			privateKey:       authorizedPrivate,
			authorityID:      authorizedID,
			expected: ExpectedResult{
				Signature: "pass", ArtifactBinding: "pass", GraphCompleteness: "fail", Authorization: "not-evaluated", PolicyEligible: false,
			},
		},
		{
			name:             "negative-complete-unauthorized",
			graph:            complete,
			statementSubject: productSubject,
			keyID:            unauthorizedKeyID,
			privateKey:       unauthorizedPrivate,
			authorityID:      unauthorizedID,
			expected: ExpectedResult{
				Signature: "pass", ArtifactBinding: "pass", GraphCompleteness: "pass", Authorization: "fail", PolicyEligible: false,
			},
		},
		{
			name:             "negative-cross-subject-substitution",
			graph:            complete,
			statementSubject: substitutedSubject,
			keyID:            authorizedKeyID,
			privateKey:       authorizedPrivate,
			authorityID:      authorizedID,
			expected: ExpectedResult{
				Signature: "pass", ArtifactBinding: "fail", GraphCompleteness: "not-evaluated", Authorization: "not-evaluated", PolicyEligible: false,
			},
		},
		{
			name:             "positive-permitted-no-action",
			graph:            noAction,
			statementSubject: productSubject,
			keyID:            authorizedKeyID,
			privateKey:       authorizedPrivate,
			authorityID:      authorizedID,
			expected: ExpectedResult{
				Signature: "pass", ArtifactBinding: "pass", GraphCompleteness: "pass", Authorization: "pass", PolicyEligible: true,
			},
		},
	}

	for _, definition := range definitions {
		fixtureDir := filepath.Join(fixturesDir, definition.name)
		if err := os.MkdirAll(fixtureDir, 0o755); err != nil {
			return err
		}
		graphPath := filepath.Join(fixtureDir, "graph.json")
		graphBytes, err := marshalJSON(definition.graph)
		if err != nil {
			return err
		}
		if err := os.WriteFile(graphPath, graphBytes, 0o644); err != nil {
			return err
		}
		graphHash := sha256.Sum256(graphBytes)
		statement := Statement{
			Type:          StatementType,
			Subject:       []Subject{definition.statementSubject},
			PredicateType: PredicateType,
			Predicate: SafetyEvidencePredicate{
				SpecVersion: "0.1.0",
				DecisionEvidenceClosureGraph: ArtifactReference{
					URI:       "graph.json",
					MediaType: "application/vnd.srac.safety-evidence-graph+json",
					Digest:    map[string]string{"sha256": hex.EncodeToString(graphHash[:])},
				},
				AnalysisRootID:        definition.graph.AnalysisRoot.ID,
				TriggerID:             definition.graph.AnalysisRoot.TriggerID,
				DeclaredClosureStatus: definition.graph.Closure.Status,
				Authorization: AuthorizationClaim{
					AuthorityID: definition.authorityID,
					DecisionID:  definition.graph.Decisions[0].ID,
				},
			},
		}
		envelope, err := SignStatement(statement, definition.keyID, definition.privateKey)
		if err != nil {
			return err
		}
		if err := writeJSON(filepath.Join(fixtureDir, "envelope.dsse.json"), envelope); err != nil {
			return err
		}
		if err := writeJSON(filepath.Join(fixtureDir, "expected.json"), definition.expected); err != nil {
			return err
		}
	}
	return nil
}

func completeGraph(subject Subject) SafetyEvidenceGraph {
	return SafetyEvidenceGraph{
		Schema: GraphSchema,
		AnalysisRoot: AnalysisRoot{
			ID:                "analysis:braking-controller-change-001",
			Subject:           subject,
			TriggerID:         "trigger:configuration-change-001",
			EvaluatedElements: []string{"component:brake-control-loop"},
		},
		Triggers: []Trigger{{
			ID: "trigger:configuration-change-001", Type: "configuration-change", URI: "https://example.org/changes/42",
		}},
		Decisions: []Decision{{
			ID:                   "decision:approve-001",
			Type:                 "approve",
			Status:               "accepted",
			AppliesTo:            []string{"component:brake-control-loop"},
			RequiredEvidence:     []string{"evidence:test-result-001"},
			RequiredVerification: []string{"verification:test-result-001"},
		}},
		Evidence: []Evidence{{
			ID:         "evidence:test-result-001",
			Digest:     map[string]string{"sha256": fixtureDigest("test-result-001")},
			Provenance: "https://example.org/ci/runs/1001",
		}},
		Verification: []Verification{{
			ID: "verification:test-result-001", EvidenceID: "evidence:test-result-001", Result: "pass",
		}},
		Closure: GraphClosure{Status: "complete"},
	}
}

func noActionGraph(subject Subject) SafetyEvidenceGraph {
	graph := completeGraph(subject)
	graph.AnalysisRoot.ID = "analysis:documentation-only-change-001"
	graph.AnalysisRoot.EvaluatedElements = []string{"requirement:diagnostic-wording"}
	graph.Decisions = []Decision{{
		ID: "decision:no-action-001", Type: "noAction", Status: "accepted", AppliesTo: []string{"requirement:diagnostic-wording"},
	}}
	graph.Evidence = []Evidence{}
	graph.Verification = []Verification{}
	return graph
}

func fixturePrivateKey(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte(label))
	return ed25519.NewKeyFromSeed(seed[:])
}

func verificationKey(keyID string, publicKey ed25519.PublicKey) VerificationKey {
	return VerificationKey{KeyID: keyID, Algorithm: "ed25519", PublicKey: base64.StdEncoding.EncodeToString(publicKey)}
}

func fixtureSubject(name, label string) Subject {
	return Subject{Name: name, Digest: map[string]string{"sha256": fixtureDigest(label)}}
}

func fixtureDigest(label string) string {
	digest := sha256.Sum256([]byte(label))
	return hex.EncodeToString(digest[:])
}

func writeJSON(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	content, err := marshalJSON(value)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, content, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func marshalJSON(value any) ([]byte, error) {
	content, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(content, '\n'), nil
}
