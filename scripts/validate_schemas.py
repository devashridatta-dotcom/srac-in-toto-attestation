#!/usr/bin/env python3
"""Validate all conformance fixtures against the published draft schemas."""

import base64
import json
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
PREDICATE_SCHEMA = json.loads(
    (ROOT / "schema" / "safety-evidence-predicate-v0.1.schema.json").read_text(encoding="utf-8")
)
GRAPH_SCHEMA = json.loads(
    (ROOT / "schema" / "safety-evidence-graph-v0.1.schema.json").read_text(encoding="utf-8")
)


def main() -> None:
    Draft202012Validator.check_schema(PREDICATE_SCHEMA)
    Draft202012Validator.check_schema(GRAPH_SCHEMA)
    predicate_validator = Draft202012Validator(PREDICATE_SCHEMA)
    graph_validator = Draft202012Validator(GRAPH_SCHEMA)

    fixture_dirs = sorted(path for path in (ROOT / "fixtures").iterdir() if path.is_dir())
    if not fixture_dirs:
        raise SystemExit("no fixture directories found")

    for fixture_dir in fixture_dirs:
        graph = json.loads((fixture_dir / "graph.json").read_text(encoding="utf-8"))
        envelope = json.loads((fixture_dir / "envelope.dsse.json").read_text(encoding="utf-8"))
        statement = json.loads(base64.b64decode(envelope["payload"], validate=True))
        graph_validator.validate(graph)
        predicate_validator.validate(statement["predicate"])

    print(f"validated {len(fixture_dirs)} signed fixture bundles against both schemas")


if __name__ == "__main__":
    main()
