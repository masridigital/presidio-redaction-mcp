# Allowlist change process

`config/allowlist.yaml` is how the no-PHI upstream scope is enforced. Changing it changes which data can leave the proxy. Marko reviews every change before merge. The current security review of this lane is NO-GO for merge and deploy until a later review clears it. Enterprise change control is POL-CHG-001. This file is the repo procedure that feeds it.

## What needs this process

- Add, remove, or edit a tool, its argument schema, result fields, pagination cap, or rationale.
- Add or rename an upstream. A third upstream fails config load today. Proposing one is a change to `docs/upstream-scope-policy.md` and needs a new Cap decision.
- Change a Composio toolkit, action id, or connected account id.
- Change `egress.upstream_hosts`. Replacing a `.invalid` pin with a routable host needs Marko review and a new Cap decision, including a check that the host is not an unverified Cloudflare path.
- Any edit that would set `phi_scope` to something other than `none`, or that would mark a tool writable.

Write, send, export, bulk, and wildcard entries are rejected when the config loads. They are not an approvable change under the current scope.

Removing or disabling a tool during an incident uses the same record: a reviewed diff, then a `config_change` audit row. Containment steps are in `docs/incident-response.md`.

## Steps

1. Open a pull request with the allowlist diff. Update `docs/upstream-scope-policy.md` in that pull request when the upstream scope changes. Update `docs/residual-risk.md` when the accepted risk changes.
2. CI must be green before review. The workflow runs pytest (acceptance tests 1–10, recall floors, streaming fail-closed), the fixture-header check, gitleaks, bandit, pip-audit, CycloneDX, and shellcheck.
3. Marko approves before merge. The review confirms all of the following:
   - The diff stays inside the written no-PHI scope. Cap's decision leaves StackJack and Composio outside BAA coverage. The review records that the change still fits that scope.
   - The tool stays read-only, with a field allowlist, and `max_items` at or under 20.
   - The diff adds no wildcard and no path that sends PHI to a party without a BAA, or that moves a PHI-capable caller onto the tunnel.
   - Egress hosts stay on pins whose path has been reviewed. Unverified vendor Cloudflare paths stay off the list.
   - `config/recall-floors.yaml` still passes on the synthetic corpus.
4. Merge follows that approval. Deploy stays closed while the security review is NO-GO. The host unit, when a later review allows install, is `deploy/systemd/presidio-redaction-mcp.service`, installed by `deploy/install.sh`.
5. The next process start writes a `config_change` audit row when the allowlist hash changes. The row carries the config hash and no argument or result text. A production allowlist that changed without that row is an incident.

## Record

The pull request, Marko's review, and the CI logs are the change record. Keep them with the repository. HIPAA documentation retention for this record is 6 years (164.316). The audit row is the runtime half of the same change; log retention is in `docs/host-hardening.md`.
