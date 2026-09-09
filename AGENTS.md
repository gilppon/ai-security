# AI Security Project Instructions

Build a proprietary defensive AI Security Control Plane centered on:

`SecurityEvent -> Normalize -> Context -> Detect -> Risk -> Policy -> Decision -> Audit`

## Non-negotiable controls

1. Default deny and least privilege.
2. Treat LLM output and external content as untrusted.
3. LLMs never make final security decisions.
4. Critical decisions are deterministic and include structured reason codes.
5. Important actions generate events; allow and deny decisions are auditable.
6. Keep modules independently replaceable.
7. Never copy third-party security project source or rule corpora.
8. New tool, network, and filesystem capabilities must pass their corresponding firewalls.
9. Never execute LLM-generated shell strings. Use `shell=False` for approved process execution.
10. Resolve filesystem paths and network destinations before authorization.
11. Never log raw secrets. Use redaction, hashes, fingerprints, and metadata.
12. Security-sensitive functions require tests. Never skip tests to make builds pass.

## Technology

Python 3.12+, FastAPI, Pydantic v2, pytest, PyYAML, structured JSON logging.

