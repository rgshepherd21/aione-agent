"""
One-shot patch for internal/actions/executor/executor.go: swap the
captureDNSState call sites from action.ID (the KAL action slug) to
action.CommandID (the per-dispatch correlation id the backend uses
as action_executions.id).

Background
----------
The state-captures endpoint on the backend validates
``action_execution_id`` as a UUID and rejects slugs with
"Input should be a valid UUID". Before this fix the agent was posting
``action_execution_id="flush_dns_cache"`` and the backend 422-ed every
capture POST. Identical root cause as the command_id fix in PR #10 —
two distinct ids were being confused.

Idempotent: if the new form is already present, exits 0 without
changes. If the anchor is missing (file drift / hand-edit), aborts.
Preserves LF/CRLF line endings.

Run from the aione-agent repo root:
    python patch_captures.py
"""

import pathlib
import sys

PATH = pathlib.Path("internal/actions/executor/executor.go")

OLD = (
    "\t\te.captureDNSState(ctx, action.ID, capture.CaptureTypePre)\n"
    "\t\tout, err := e.flushDNSCache(ctx, action.Params)\n"
    "\t\te.captureDNSState(ctx, action.ID, capture.CaptureTypePost)\n"
)

NEW = (
    "\t\t// Pass action.CommandID (the per-dispatch correlation id that\n"
    "\t\t// equals action_executions.id on the backend) -- NOT action.ID\n"
    "\t\t// (the KAL action slug). The state-captures endpoint validates\n"
    "\t\t// action_execution_id as a UUID; sending a slug 422s the POST.\n"
    "\t\te.captureDNSState(ctx, action.CommandID, capture.CaptureTypePre)\n"
    "\t\tout, err := e.flushDNSCache(ctx, action.Params)\n"
    "\t\te.captureDNSState(ctx, action.CommandID, capture.CaptureTypePost)\n"
)


def main() -> int:
    if not PATH.exists():
        print(f"error: {PATH} not found (run from aione-agent repo root)", file=sys.stderr)
        return 2

    raw = PATH.read_bytes()
    uses_crlf = b"\r\n" in raw
    text = raw.decode("utf-8").replace("\r\n", "\n")

    if NEW in text:
        print("already patched; no changes made")
        return 0

    if OLD not in text:
        print("error: anchor block not found; aborting", file=sys.stderr)
        return 3

    text = text.replace(OLD, NEW, 1)

    if uses_crlf:
        text = text.replace("\n", "\r\n")
    PATH.write_bytes(text.encode("utf-8"))
    print(f"edit applied ({'CRLF' if uses_crlf else 'LF'} line endings preserved)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
