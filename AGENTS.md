
<!-- security-audit-gate -->
## Security review gate

For code changes, use the installed `security-audit` skill to review the affected trust boundaries. Before a commit, stage the exact source, compute its digest with `.security-audit/security_gate.py`, and record that value as `source_ref.index_digest` in the full standard or deep audit's `run-metadata.json`. Keep the Cloudflare report outside the repository. When the audit is complete, run `python3 .security-audit/security_gate.py attest /absolute/path/to/audit/run` and stage the generated attestation. Do not claim that a passing hook proves the absence of vulnerabilities. Resolve confirmed high or critical findings before attesting. Review `needs_validation` items with the owner rather than silently treating them as safe.
