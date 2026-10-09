package profile

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const (
	StatementType = "https://in-toto.io/Statement/v1"
	PredicateType = "https://github.com/devashridatta-dotcom/srac-in-toto-attestation/predicate/safety-evidence/v0.1"
	PayloadType   = "application/vnd.in-toto+json"
	GraphSchema   = "https://github.com/devashridatta-dotcom/srac-in-toto-attestation/schema/safety-evidence-graph-v0.1"
)

type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []Signature `json:"signatures"`
}

type Signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

type Statement struct {
	Type          string                  `json:"_type"`
	Subject       []Subject               `json:"subject"`
	PredicateType string                  `json:"predicateType"`
	Predicate     SafetyEvidencePredicate `json:"predicate"`
}

type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type SafetyEvidencePredicate struct {
	SpecVersion                  string             `json:"specVersion"`
	DecisionEvidenceClosureGraph ArtifactReference  `json:"decisionEvidenceClosureGraph"`
	AnalysisRootID               string             `json:"analysisRootId"`
	TriggerID                    string             `json:"triggerId"`
	DeclaredClosureStatus        string             `json:"declaredClosureStatus"`
	Authorization                AuthorizationClaim `json:"authorization"`
}

type ArtifactReference struct {
	URI       string            `json:"uri"`
	MediaType string            `json:"mediaType"`
	Digest    map[string]string `json:"digest"`
}

type AuthorizationClaim struct {
	AuthorityID string `json:"authorityId"`
	DecisionID  string `json:"decisionId"`
}

type SafetyEvidenceGraph struct {
	Schema       string         `json:"schema"`
	AnalysisRoot AnalysisRoot   `json:"analysisRoot"`
	Triggers     []Trigger      `json:"triggers"`
	Decisions    []Decision     `json:"decisions"`
	Evidence     []Evidence     `json:"evidence"`
	Verification []Verification `json:"verification"`
	Closure      GraphClosure   `json:"closure"`
}

type AnalysisRoot struct {
	ID                string   `json:"id"`
	Subject           Subject  `json:"subject"`
	TriggerID         string   `json:"triggerId"`
	EvaluatedElements []string `json:"evaluatedElements"`
}

type Trigger struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	URI  string `json:"uri,omitempty"`
}

type Decision struct {
	ID                   string   `json:"id"`
	Type                 string   `json:"type"`
	Status               string   `json:"status"`
	AppliesTo            []string `json:"appliesTo"`
	RequiredEvidence     []string `json:"requiredEvidence,omitempty"`
	RequiredVerification []string `json:"requiredVerification,omitempty"`
}

type Evidence struct {
	ID         string            `json:"id"`
	Digest     map[string]string `json:"digest"`
	Provenance string            `json:"provenance"`
}

type Verification struct {
	ID         string `json:"id"`
	EvidenceID string `json:"evidenceId"`
	Result     string `json:"result"`
}

type GraphClosure struct {
	Status string `json:"status"`
}

type Policy struct {
	VerificationKeys             []VerificationKey  `json:"verificationKeys"`
	AuthorizedSigners            []AuthorizedSigner `json:"authorizedSigners"`
	AllowNoActionWithoutEvidence bool               `json:"allowNoActionWithoutEvidence"`
}

type VerificationKey struct {
	KeyID     string `json:"keyId"`
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"publicKey"`
}

type AuthorizedSigner struct {
	KeyID       string `json:"keyId"`
	AuthorityID string `json:"authorityId"`
}

type VerificationResult struct {
	Fixture           string   `json:"fixture,omitempty"`
	Signature         string   `json:"signature"`
	ArtifactBinding   string   `json:"artifactBinding"`
	GraphCompleteness string   `json:"graphCompleteness"`
	Authorization     string   `json:"authorization"`
	PolicyEligible    bool     `json:"policyEligible"`
	SafetyClaimTruth  string   `json:"safetyClaimTruth"`
	Errors            []string `json:"errors,omitempty"`
}

type ExpectedResult struct {
	Signature         string `json:"signature"`
	ArtifactBinding   string `json:"artifactBinding"`
	GraphCompleteness string `json:"graphCompleteness"`
	Authorization     string `json:"authorization"`
	PolicyEligible    bool   `json:"policyEligible"`
}

func SignStatement(statement Statement, keyID string, privateKey ed25519.PrivateKey) (Envelope, error) {
	payload, err := json.Marshal(statement)
	if err != nil {
		return Envelope{}, err
	}
	signature := ed25519.Sign(privateKey, pae(PayloadType, payload))
	return Envelope{
		PayloadType: PayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures: []Signature{{
			KeyID: keyID,
			Sig:   base64.StdEncoding.EncodeToString(signature),
		}},
	}, nil
}

func VerifyFiles(envelopePath, bundleDir, policyPath string) (VerificationResult, error) {
	envelopeBytes, err := os.ReadFile(envelopePath)
	if err != nil {
		return VerificationResult{}, err
	}
	policyBytes, err := os.ReadFile(policyPath)
	if err != nil {
		return VerificationResult{}, err
	}
	var envelope Envelope
	if err := strictUnmarshal(envelopeBytes, &envelope); err != nil {
		return VerificationResult{}, fmt.Errorf("decode envelope: %w", err)
	}
	var policy Policy
	if err := strictUnmarshal(policyBytes, &policy); err != nil {
		return VerificationResult{}, fmt.Errorf("decode policy: %w", err)
	}
	return Verify(envelope, bundleDir, policy), nil
}

func Verify(envelope Envelope, bundleDir string, policy Policy) VerificationResult {
	result := VerificationResult{
		Signature:         "fail",
		ArtifactBinding:   "not-evaluated",
		GraphCompleteness: "not-evaluated",
		Authorization:     "not-evaluated",
		SafetyClaimTruth:  "not-evaluated",
	}
	payload, validKeyID, err := verifyEnvelope(envelope, policy)
	if err != nil {
		result.Errors = append(result.Errors, err.Error())
		return result
	}
	result.Signature = "pass"

	var statement Statement
	if err := strictUnmarshal(payload, &statement); err != nil {
		result.Errors = append(result.Errors, "decode statement: "+err.Error())
		return result
	}
	if err := validateStatement(statement); err != nil {
		result.Errors = append(result.Errors, err.Error())
		return result
	}

	graphBytes, err := readBundleArtifact(bundleDir, statement.Predicate.DecisionEvidenceClosureGraph.URI)
	if err != nil {
		result.ArtifactBinding = "fail"
		result.Errors = append(result.Errors, err.Error())
		return result
	}
	if err := validateDigest(graphBytes, statement.Predicate.DecisionEvidenceClosureGraph.Digest); err != nil {
		result.ArtifactBinding = "fail"
		result.Errors = append(result.Errors, err.Error())
		return result
	}
	var graph SafetyEvidenceGraph
	if err := strictUnmarshal(graphBytes, &graph); err != nil {
		result.ArtifactBinding = "fail"
		result.Errors = append(result.Errors, "decode graph: "+err.Error())
		return result
	}
	if err := validateBindings(statement, graph); err != nil {
		result.ArtifactBinding = "fail"
		result.Errors = append(result.Errors, err.Error())
		return result
	}
	result.ArtifactBinding = "pass"

	if err := validateGraph(graph, policy); err != nil {
		result.GraphCompleteness = "fail"
		result.Errors = append(result.Errors, err.Error())
		return result
	}
	result.GraphCompleteness = "pass"

	if err := validateAuthorization(validKeyID, statement.Predicate, graph, policy); err != nil {
		result.Authorization = "fail"
		result.Errors = append(result.Errors, err.Error())
		return result
	}
	result.Authorization = "pass"
	result.PolicyEligible = true
	return result
}

func VerifySuite(fixturesDir, policyPath string) ([]VerificationResult, error) {
	entries, err := os.ReadDir(fixturesDir)
	if err != nil {
		return nil, err
	}
	var results []VerificationResult
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		fixtureDir := filepath.Join(fixturesDir, entry.Name())
		result, err := VerifyFiles(filepath.Join(fixtureDir, "envelope.dsse.json"), fixtureDir, policyPath)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", entry.Name(), err)
		}
		result.Fixture = entry.Name()
		expectedBytes, err := os.ReadFile(filepath.Join(fixtureDir, "expected.json"))
		if err != nil {
			return nil, err
		}
		var expected ExpectedResult
		if err := strictUnmarshal(expectedBytes, &expected); err != nil {
			return nil, err
		}
		if !matchesExpected(result, expected) {
			return nil, fmt.Errorf("%s: result does not match expected outcome: got %+v expected %+v", entry.Name(), result, expected)
		}
		results = append(results, result)
	}
	sort.Slice(results, func(i, j int) bool { return results[i].Fixture < results[j].Fixture })
	if len(results) == 0 {
		return nil, errors.New("no conformance fixtures found")
	}
	return results, nil
}

func verifyEnvelope(envelope Envelope, policy Policy) ([]byte, string, error) {
	if envelope.PayloadType != PayloadType {
		return nil, "", fmt.Errorf("unsupported payload type %q", envelope.PayloadType)
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return nil, "", fmt.Errorf("decode payload: %w", err)
	}
	keys := make(map[string]ed25519.PublicKey)
	for _, key := range policy.VerificationKeys {
		if key.Algorithm != "ed25519" {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(key.PublicKey)
		if err != nil || len(decoded) != ed25519.PublicKeySize {
			continue
		}
		keys[key.KeyID] = ed25519.PublicKey(decoded)
	}
	for _, candidate := range envelope.Signatures {
		publicKey, ok := keys[candidate.KeyID]
		if !ok {
			continue
		}
		signature, err := base64.StdEncoding.DecodeString(candidate.Sig)
		if err != nil {
			continue
		}
		if ed25519.Verify(publicKey, pae(envelope.PayloadType, payload), signature) {
			return payload, candidate.KeyID, nil
		}
	}
	return nil, "", errors.New("no valid DSSE signature from a known verification key")
}

func validateStatement(statement Statement) error {
	if statement.Type != StatementType {
		return fmt.Errorf("unsupported statement type %q", statement.Type)
	}
	if statement.PredicateType != PredicateType {
		return fmt.Errorf("unsupported predicate type %q", statement.PredicateType)
	}
	if statement.Predicate.SpecVersion != "0.1.0" {
		return fmt.Errorf("unsupported predicate version %q", statement.Predicate.SpecVersion)
	}
	if len(statement.Subject) == 0 {
		return errors.New("statement requires at least one subject")
	}
	if statement.Predicate.DecisionEvidenceClosureGraph.MediaType != "application/vnd.srac.safety-evidence-graph+json" {
		return errors.New("unsupported decision/evidence graph media type")
	}
	return nil
}

func validateBindings(statement Statement, graph SafetyEvidenceGraph) error {
	if graph.Schema != GraphSchema {
		return fmt.Errorf("unsupported graph schema %q", graph.Schema)
	}
	if statement.Predicate.AnalysisRootID != graph.AnalysisRoot.ID {
		return errors.New("analysis-root binding mismatch")
	}
	if statement.Predicate.TriggerID != graph.AnalysisRoot.TriggerID {
		return errors.New("trigger binding mismatch")
	}
	if statement.Predicate.DeclaredClosureStatus != graph.Closure.Status {
		return errors.New("declared closure status does not match graph")
	}
	expectedDigest := graph.AnalysisRoot.Subject.Digest["sha256"]
	for _, subject := range statement.Subject {
		if subject.Name == graph.AnalysisRoot.Subject.Name && subject.Digest["sha256"] == expectedDigest {
			return nil
		}
	}
	return errors.New("statement subject does not match the graph subject")
}

func validateGraph(graph SafetyEvidenceGraph, policy Policy) error {
	if graph.AnalysisRoot.ID == "" || graph.AnalysisRoot.TriggerID == "" {
		return errors.New("analysis root and trigger are required")
	}
	if graph.Closure.Status != "complete" {
		return fmt.Errorf("graph closure is %q, not complete", graph.Closure.Status)
	}
	triggerFound := false
	for _, trigger := range graph.Triggers {
		if trigger.ID == graph.AnalysisRoot.TriggerID {
			triggerFound = true
		}
	}
	if !triggerFound {
		return errors.New("analysis trigger is unresolved")
	}
	elements := stringSet(graph.AnalysisRoot.EvaluatedElements)
	if len(elements) == 0 {
		return errors.New("analysis root has no evaluated elements")
	}
	evidence := make(map[string]Evidence)
	for _, item := range graph.Evidence {
		if item.ID == "" || !validSHA256(item.Digest["sha256"]) || item.Provenance == "" {
			return fmt.Errorf("evidence %q is missing digest or provenance", item.ID)
		}
		if _, duplicate := evidence[item.ID]; duplicate {
			return fmt.Errorf("duplicate evidence id %q", item.ID)
		}
		evidence[item.ID] = item
	}
	verification := make(map[string]Verification)
	for _, item := range graph.Verification {
		if item.ID == "" {
			return errors.New("verification id is required")
		}
		if _, duplicate := verification[item.ID]; duplicate {
			return fmt.Errorf("duplicate verification id %q", item.ID)
		}
		if _, ok := evidence[item.EvidenceID]; !ok {
			return fmt.Errorf("verification %q references missing evidence %q", item.ID, item.EvidenceID)
		}
		if item.Result != "pass" {
			return fmt.Errorf("verification %q did not pass", item.ID)
		}
		verification[item.ID] = item
	}
	covered := make(map[string]bool)
	decisionIDs := make(map[string]bool)
	for _, decision := range graph.Decisions {
		if decision.ID == "" || decisionIDs[decision.ID] {
			return fmt.Errorf("missing or duplicate decision id %q", decision.ID)
		}
		decisionIDs[decision.ID] = true
		if decision.Status != "accepted" {
			return fmt.Errorf("decision %q is not accepted", decision.ID)
		}
		if len(decision.AppliesTo) == 0 {
			return fmt.Errorf("decision %q does not apply to an evaluated element", decision.ID)
		}
		for _, element := range decision.AppliesTo {
			if !elements[element] {
				return fmt.Errorf("decision %q references unevaluated element %q", decision.ID, element)
			}
			covered[element] = true
		}
		if decision.Type == "noAction" && policy.AllowNoActionWithoutEvidence {
			continue
		}
		if len(decision.RequiredEvidence) == 0 {
			return fmt.Errorf("decision %q has no required evidence", decision.ID)
		}
		for _, evidenceID := range decision.RequiredEvidence {
			if _, ok := evidence[evidenceID]; !ok {
				return fmt.Errorf("decision %q references missing evidence %q", decision.ID, evidenceID)
			}
		}
		if len(decision.RequiredVerification) == 0 {
			return fmt.Errorf("decision %q has no required verification", decision.ID)
		}
		for _, verificationID := range decision.RequiredVerification {
			resolvedVerification, ok := verification[verificationID]
			if !ok {
				return fmt.Errorf("decision %q references missing verification %q", decision.ID, verificationID)
			}
			if !contains(decision.RequiredEvidence, resolvedVerification.EvidenceID) {
				return fmt.Errorf("verification %q does not cover required evidence for decision %q", verificationID, decision.ID)
			}
		}
	}
	for element := range elements {
		if !covered[element] {
			return fmt.Errorf("evaluated element %q has no closure decision", element)
		}
	}
	return nil
}

func validateAuthorization(keyID string, predicate SafetyEvidencePredicate, graph SafetyEvidenceGraph, policy Policy) error {
	authorized := false
	for _, signer := range policy.AuthorizedSigners {
		if signer.KeyID == keyID && signer.AuthorityID == predicate.Authorization.AuthorityID {
			authorized = true
		}
	}
	if !authorized {
		return fmt.Errorf("signer %q is not authorized for authority %q", keyID, predicate.Authorization.AuthorityID)
	}
	for _, decision := range graph.Decisions {
		if decision.ID == predicate.Authorization.DecisionID && decision.Status == "accepted" {
			return nil
		}
	}
	return errors.New("authorization decision is absent or not accepted")
}

func validateDigest(content []byte, digest map[string]string) error {
	expected := digest["sha256"]
	if !validSHA256(expected) {
		return errors.New("graph reference has an invalid SHA-256 digest")
	}
	actual := sha256.Sum256(content)
	if hex.EncodeToString(actual[:]) != expected {
		return errors.New("decision/evidence graph digest mismatch")
	}
	return nil
}

func readBundleArtifact(bundleDir, uri string) ([]byte, error) {
	if uri == "" || filepath.IsAbs(uri) {
		return nil, errors.New("graph URI must be a relative bundle path")
	}
	clean := filepath.Clean(filepath.FromSlash(uri))
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return nil, errors.New("graph URI escapes the bundle directory")
	}
	base, err := filepath.Abs(bundleDir)
	if err != nil {
		return nil, err
	}
	path, err := filepath.Abs(filepath.Join(base, clean))
	if err != nil {
		return nil, err
	}
	rel, err := filepath.Rel(base, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, errors.New("graph URI escapes the bundle directory")
	}
	return os.ReadFile(path)
}

func strictUnmarshal(content []byte, target any) error {
	decoder := json.NewDecoder(strings.NewReader(string(content)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("unexpected trailing JSON content")
		}
		return err
	}
	return nil
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func pae(payloadType string, payload []byte) []byte {
	prefix := "DSSEv1 " + strconv.Itoa(len(payloadType)) + " " + payloadType + " " + strconv.Itoa(len(payload)) + " "
	return append([]byte(prefix), payload...)
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func stringSet(values []string) map[string]bool {
	result := make(map[string]bool, len(values))
	for _, value := range values {
		if value != "" {
			result[value] = true
		}
	}
	return result
}

func matchesExpected(actual VerificationResult, expected ExpectedResult) bool {
	return actual.Signature == expected.Signature &&
		actual.ArtifactBinding == expected.ArtifactBinding &&
		actual.GraphCompleteness == expected.GraphCompleteness &&
		actual.Authorization == expected.Authorization &&
		actual.PolicyEligible == expected.PolicyEligible
}
