#!/usr/bin/env python3
"""Classify fresh observations against preserved identities; never execute a launch."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import time

REVOKED = {314473, 314474, 314476, 314478, 314481, 314484, 314490}
HELD = {313173}


def reconcile(evidence, now=None):
    now = time.time() if now is None else now
    blockers = []
    required = ["source_snapshot_sha256", "chain_finalized_block", "chain_observed_at", "process_observed_at",
                "authority_fenced", "journal_reconciled", "wallets", "jobs", "transactions"]
    if any(field not in evidence for field in required):
        return {"schema": 1, "live_actions_allowed": False, "blockers": ["incomplete-evidence"], "jobs": []}
    if not evidence["authority_fenced"]:
        blockers.append("old-controller-not-proven-fenced")
    if not evidence["journal_reconciled"]:
        blockers.append("preserved-journals-not-reconciled")
    if not evidence["chain_finalized_block"] or not evidence["source_snapshot_sha256"]:
        blockers.append("unbound-evidence")
    for field in ("chain_observed_at", "process_observed_at"):
        age = now - evidence[field]
        if age < 0 or age > 180:
            blockers.append("stale-" + field)
    tx_rows = []
    seen_tx = set()
    for tx in evidence["transactions"]:
        tx_hash = tx.get("hash")
        if not tx_hash or tx_hash in seen_tx:
            blockers.append("missing-or-duplicate-transaction-reference")
        seen_tx.add(tx_hash)
        status = tx.get("status")
        if status not in ("finalized-success", "finalized-failure", "proved-never-broadcast"):
            blockers.append("unresolved-transaction-do-not-replay")
        tx_rows.append({"hash": tx_hash, "status": status, "replay_allowed": False})
    roles = [w.get("role") for w in evidence["wallets"]]
    if len(roles) != len(set(roles)) or "rental_wallet" not in roles:
        blockers.append("wallet-role-reconciliation-required")
    rows, active_ids, active_ips, seen_jobs = [], set(), set(), set()
    for job in evidence["jobs"]:
        job_id = int(job["job_id"])
        reasons = []
        if job_id in seen_jobs:
            reasons.append("duplicate-job-row")
        seen_jobs.add(job_id)
        if job_id in REVOKED or job.get("admission_revoked"):
            reasons.append("admission-revoked-preserve-revocation")
        if job_id in HELD or job.get("quarantined") or job.get("held"):
            reasons.append("held-or-quarantined")
        if not job.get("original_identity_matches") or not job.get("canonical_profile_hash"):
            reasons.append("canonical-identity-unverified")
        if not job.get("processor_matches") or not job.get("expected_ip_matches"):
            reasons.append("processor-or-ip-unverified")
        if job.get("lease_end", 0) <= now or job.get("assignment") != "active-acknowledged":
            reasons.append("assignment-expired-absent-or-unacknowledged")
        process = job.get("process")
        if process not in ("running-matching-identity", "independently-proved-stopped"):
            reasons.append("physical-process-state-unknown")
        identity = job.get("canonical_profile_hash")
        ip = job.get("observed_ip")
        if not ip:
            reasons.append("observed-ip-missing")
        if process == "running-matching-identity":
            if identity in active_ids or ip in active_ips:
                reasons.append("duplicate-live-identity-or-ip")
                blockers.append("duplicate-live-identity-or-ip")
            active_ids.add(identity); active_ips.add(ip)
        if reasons or blockers:
            decision = "hold"
        elif process == "running-matching-identity":
            decision = "adopt-candidate-do-not-launch"
        else:
            decision = "review-for-existing-admission-controller"
        rows.append({"job_id": job_id, "decision": decision, "reasons": reasons, "launch_allowed": False})
    if blockers:
        for row in rows:
            row["decision"] = "hold"
    return {"schema": 1, "created_epoch": now, "live_actions_allowed": False,
            "blockers": sorted(set(blockers)), "transactions": tx_rows, "jobs": rows,
            "note": "Read-only review plan. No signatures, transactions, renewals, identities, admissions or processes created."}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    source = Path(args.evidence)
    report = reconcile(json.loads(source.read_text()))
    report["evidence_sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
    out = Path(args.out)
    with out.open("x") as stream:
        json.dump(report, stream, indent=2)
    print(json.dumps({"output": str(out), "jobs": len(report["jobs"]), "blockers": report["blockers"], "live_actions_allowed": False}))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("Reconciliation failed closed; no live action performed.", file=sys.stderr)
        sys.exit(1)

