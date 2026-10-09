package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/devashridatta-dotcom/srac-in-toto-attestation/internal/profile"
)

const version = "0.1.0"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return usageError()
	}
	switch args[0] {
	case "version", "--version", "-v":
		fmt.Println(version)
		return nil
	case "generate-fixtures":
		fs := flag.NewFlagSet("generate-fixtures", flag.ContinueOnError)
		output := fs.String("output", "fixtures", "fixture output directory")
		policy := fs.String("policy", "policy/example-policy.json", "example policy output path")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		return profile.GenerateDemo(*output, *policy)
	case "verify":
		fs := flag.NewFlagSet("verify", flag.ContinueOnError)
		envelope := fs.String("envelope", "", "DSSE envelope path")
		bundle := fs.String("bundle-dir", "", "directory containing referenced graph artifacts")
		policy := fs.String("policy", "policy/example-policy.json", "verification policy path")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *envelope == "" || *bundle == "" {
			return fmt.Errorf("--envelope and --bundle-dir are required")
		}
		result, err := profile.VerifyFiles(*envelope, *bundle, *policy)
		if err != nil {
			return err
		}
		if err := printJSON(result); err != nil {
			return err
		}
		if !result.PolicyEligible {
			return fmt.Errorf("claim is not policy eligible")
		}
		return nil
	case "verify-suite":
		fs := flag.NewFlagSet("verify-suite", flag.ContinueOnError)
		fixtures := fs.String("fixtures", "fixtures", "conformance fixture directory")
		policy := fs.String("policy", "policy/example-policy.json", "verification policy path")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		results, err := profile.VerifySuite(*fixtures, *policy)
		if err != nil {
			return err
		}
		return printJSON(results)
	default:
		return usageError()
	}
}

func printJSON(value any) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func usageError() error {
	return fmt.Errorf("usage: srac-attest <generate-fixtures|verify|verify-suite|version>")
}
