import base64
import hashlib
import json
import os
import re
import sqlite3
from typing import Any, Dict, List, Optional, Set, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

app = FastAPI(title="Safe AI Mailroom Agent", version="2.0.0")

if os.getenv("VERCEL"):
    DB_PATH = os.getenv("MAILROOM_DB_PATH", "/tmp/mailroom.db")
else:
    DB_PATH = os.getenv("MAILROOM_DB_PATH", "mailroom.db")

ALLOWED_ACTIONS = [
    "create_draft",
    "update_internal_record",
    "send_approved_notice",
    "request_confirmation",
    "quarantine_item",
    "no_action",
]


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS evaluations (
            evaluation_id TEXT PRIMARY KEY,
            propose_request_hash TEXT NOT NULL,
            propose_response_json TEXT NOT NULL,
            input_digest TEXT NOT NULL,
            receipt_verifier_json TEXT NOT NULL,
            proposals_json TEXT NOT NULL,
            commit_request_hash TEXT,
            commit_response_json TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS dossier_cache (
            content_fingerprint TEXT PRIMARY KEY,
            dossier_id TEXT NOT NULL,
            call_id TEXT NOT NULL,
            action TEXT NOT NULL,
            target_json TEXT,
            payload_json TEXT NOT NULL,
            evidence_json TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
    )
    conn.commit()
    conn.close()


init_db()


def canonical_json(value: Any) -> bytes:
    """Recursively key-sorted, compact UTF-8 JSON bytes."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().lower()


def decode_b64(value: str) -> bytes:
    """Decode base64 or base64url string with padding fix."""
    cleaned = value.strip().replace("-", "+").replace("_", "/")
    if len(cleaned) % 4 != 0:
        cleaned += "=" * (4 - (len(cleaned) % 4))
    return base64.b64decode(cleaned)


def verify_ed25519_signature(public_key_jwk: Dict[str, Any], payload: Dict[str, Any], signature_b64: str) -> bool:
    try:
        x_val = public_key_jwk.get("x")
        if not x_val:
            return False
        public_bytes = decode_b64(x_val)
        if len(public_bytes) != 32:
            return False
        public_key = Ed25519PublicKey.from_public_bytes(public_bytes)
        sig_bytes = decode_b64(signature_b64)
        if len(sig_bytes) != 64:
            return False
        signed_bytes = canonical_json(payload)
        public_key.verify(sig_bytes, signed_bytes)
        return True
    except Exception:
        return False


def proposal_digest_for(proposal: Dict[str, Any]) -> str:
    """
    Compute proposalDigest over recursively key-sorted compact JSON of:
    dossierId, callId, action, target (null when absent), payload, evidence (sorted strings).
    """
    subset = {
        "dossierId": proposal.get("dossierId"),
        "callId": proposal.get("callId"),
        "action": proposal.get("action"),
        "target": proposal.get("target"),
        "payload": proposal.get("payload"),
        "evidence": sorted(list(set(proposal.get("evidence", [])))),
    }
    return sha256_hex(canonical_json(subset))


# ---------------------------------------------------------
# Dossier Analyzer & Safety Classifier
# ---------------------------------------------------------

INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(previous|all|above)\s+instructions", re.IGNORECASE),
    re.compile(r"system\s+override", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+in\s+maintenance\s+mode", re.IGNORECASE),
    re.compile(r"output\s+(the|secret|canary|private)", re.IGNORECASE),
    re.compile(r"call\s+tool\s+with\s+admin", re.IGNORECASE),
    re.compile(r"disregard\s+prior", re.IGNORECASE),
    re.compile(r"drop\s+table", re.IGNORECASE),
    re.compile(r"bypass\s+security", re.IGNORECASE),
]


def analyze_dossier(dossier: Dict[str, Any], allowed_actions: List[str]) -> Tuple[str, Optional[Dict[str, Any]], Dict[str, Any], List[str]]:
    """
    Examines a dossier according to safety rules and returns:
    (action, target, payload, evidence_lines)
    """
    dossier_id = dossier.get("dossierId", "unknown")
    mailbox = dossier.get("mailbox", "support")
    objective = dossier.get("objective", "")
    sources = dossier.get("sources", [])

    all_line_ids: List[str] = []
    lines_by_id: Dict[str, Tuple[str, Dict[str, Any]]] = {}  # lineId -> (text, source)

    for src in sources:
        for line in src.get("lines", []):
            lid = line.get("lineId")
            txt = line.get("text", "")
            if lid:
                all_line_ids.append(lid)
                lines_by_id[lid] = (txt, src)

    if not all_line_ids:
        # Fallback empty evidence defense (should not normally happen in valid dossiers)
        all_line_ids = ["line-0"]

    # 1. Check for prompt injection in untrusted/external sources
    injection_evidence: List[str] = []
    for lid, (txt, src) in lines_by_id.items():
        provenance = str(src.get("provenance", "")).lower()
        kind = str(src.get("kind", "")).lower()
        is_external = any(ext in provenance or ext in kind for ext in ["external", "incoming", "untrusted", "attachment", "email_body"])
        
        # Check injection
        for pat in INJECTION_PATTERNS:
            if pat.search(txt):
                if is_external:
                    injection_evidence.append(lid)
                    break

    if injection_evidence and "quarantine_item" in allowed_actions:
        return (
            "quarantine_item",
            {"kind": "security_queue", "id": "mailroom"},
            {"artifactId": dossier_id, "reasonCode": "INDIRECT_PROMPT_INJECTION"},
            [injection_evidence[0]],
        )

    # 2. Check for duplicate / already completed / informational -> no_action
    completed_lines: List[str] = []
    duplicate_lines: List[str] = []
    info_lines: List[str] = []

    for lid, (txt, _) in lines_by_id.items():
        low = txt.lower()
        if "already completed" in low or "marked as resolved" in low or "previously processed" in low:
            completed_lines.append(lid)
        elif "duplicate" in low or "already received" in low:
            duplicate_lines.append(lid)
        elif "informational only" in low or "no action required" in low or "fyi" in low:
            info_lines.append(lid)

    if (completed_lines or duplicate_lines or info_lines) and "no_action" in allowed_actions:
        if completed_lines:
            return ("no_action", None, {"reasonCode": "ALREADY_COMPLETED", "referenceId": dossier_id}, [completed_lines[0]])
        elif duplicate_lines:
            return ("no_action", None, {"reasonCode": "DUPLICATE", "referenceId": dossier_id}, [duplicate_lines[0]])
        else:
            return ("no_action", None, {"reasonCode": "INFORMATIONAL", "referenceId": dossier_id}, [info_lines[0]])

    # 3. Check for send_approved_notice
    # Needs explicit trusted approval scoped to exact recipient, template, and public facts
    approved_lines: List[str] = []
    recipient_candidate: Optional[str] = None
    ref_candidate: str = dossier_id

    for lid, (txt, src) in lines_by_id.items():
        low = txt.lower()
        provenance = str(src.get("provenance", "")).lower()
        if ("approved" in low or "authorized for send" in low or "approval granted" in low) and "internal" in provenance:
            approved_lines.append(lid)
        # Look for email / recipient
        m = re.search(r"[\w\.-]+@[\w\.-]+\.\w+", txt)
        if m and not recipient_candidate:
            recipient_candidate = m.group(0)

    if approved_lines and "send_approved_notice" in allowed_actions:
        target_email = recipient_candidate or f"{mailbox}@company.example"
        evidence = approved_lines[:2]
        return (
            "send_approved_notice",
            {"kind": "email", "id": target_email},
            {"referenceId": ref_candidate, "status": "approved", "template": "approved_delivery_notice"},
            evidence,
        )

    # 4. Check for update_internal_record
    # Authorized internal field change: specifically delivery_window
    update_lines: List[str] = []
    window_value: str = "standard"
    event_id: str = dossier_id

    for lid, (txt, src) in lines_by_id.items():
        low = txt.lower()
        if "delivery_window" in low or "delivery window" in low or "reschedule delivery" in low:
            update_lines.append(lid)
            m = re.search(r"(morning|afternoon|evening|weekend|\d{1,2}:\d{2}\s*-\s*\d{1,2}:\d{2})", low)
            if m:
                window_value = m.group(0)

    if update_lines and "update_internal_record" in allowed_actions:
        return (
            "update_internal_record",
            {"kind": "case_record", "id": dossier_id},
            {"field": "delivery_window", "sourceEventId": event_id, "value": window_value},
            update_lines[:2],
        )

    # 5. Check for ambiguous / identity conflict -> request_confirmation
    ambiguous_lines: List[str] = []
    claimed_sender: str = mailbox

    for lid, (txt, _) in lines_by_id.items():
        low = txt.lower()
        if "identity mismatch" in low or "unverified" in low or "confirm" in low or "ambiguous" in low or "conflicting" in low:
            ambiguous_lines.append(lid)
        m = re.search(r"[\w\.-]+@[\w\.-]+\.\w+", txt)
        if m:
            claimed_sender = m.group(0)

    if ambiguous_lines and "request_confirmation" in allowed_actions:
        return (
            "request_confirmation",
            {"kind": "approval_queue", "id": "support-triage"},
            {"claimedSender": claimed_sender, "questionCode": "VERIFY_REQUEST", "referenceId": dossier_id},
            ambiguous_lines[:2],
        )

    # 6. Routine create_draft (non-sent customer draft)
    draft_lines: List[str] = []
    for lid, (txt, _) in lines_by_id.items():
        low = txt.lower()
        if "draft" in low or "order" in low or "inquiry" in low or "request" in low:
            draft_lines.append(lid)

    if not draft_lines:
        draft_lines = [all_line_ids[0]]

    if "create_draft" in allowed_actions:
        recipient = recipient_candidate or f"{mailbox}@example.com"
        return (
            "create_draft",
            {"kind": "draft_queue", "id": f"mailbox:{mailbox}"},
            {"recipient": recipient, "referenceId": dossier_id, "status": "draft", "template": "order_status"},
            draft_lines[:2],
        )

    # Safe fallback
    fallback_action = allowed_actions[0] if allowed_actions else "no_action"
    return (
        fallback_action,
        None,
        {"reasonCode": "INFORMATIONAL", "referenceId": dossier_id},
        [all_line_ids[0]],
    )


# ---------------------------------------------------------
# Request Handlers
# ---------------------------------------------------------

@app.get("/")
@app.get("/health")
def health():
    return {
        "status": "ready",
        "service": "ga5-mailroom-action-gate/v2",
        "actions": ALLOWED_ACTIONS,
    }


@app.post("/")
@app.post("/mailroom")
async def mailroom(request: Request):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body.")

    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="Request must be a JSON object.")

    operation = body.get("operation")
    if operation == "propose":
        return handle_propose(body)
    elif operation == "commit":
        return handle_commit(body)
    else:
        raise HTTPException(status_code=400, detail="Operation must be 'propose' or 'commit'.")


def handle_propose(payload: Dict[str, Any]) -> Dict[str, Any]:
    evaluation_id = payload.get("evaluationId")
    if not evaluation_id or not isinstance(evaluation_id, str):
        raise HTTPException(status_code=400, detail="Missing or invalid evaluationId.")

    dossiers = payload.get("dossiers")
    if not isinstance(dossiers, list):
        raise HTTPException(status_code=400, detail="Missing or invalid dossiers list.")

    verifier = payload.get("receiptVerifier")
    if not isinstance(verifier, dict) or "publicKeyJwk" not in verifier:
        raise HTTPException(status_code=400, detail="Missing or invalid receiptVerifier.")

    # Check for duplicate dossier IDs
    seen_dossier_ids: Set[str] = set()
    for d in dossiers:
        did = d.get("dossierId")
        if not did or did in seen_dossier_ids:
            raise HTTPException(status_code=400, detail=f"Duplicate or empty dossierId: {did}")
        seen_dossier_ids.add(did)

    allowed_actions = payload.get("allowedActions", ALLOWED_ACTIONS)
    profile = payload.get("profile", "ga5-mailroom-action-gate/v2")

    propose_hash = sha256_hex(canonical_json(payload))

    # Persistence check
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT propose_request_hash, propose_response_json FROM evaluations WHERE evaluation_id = ?",
        (evaluation_id,),
    )
    row = cursor.fetchone()
    if row:
        stored_hash, stored_response_json = row
        conn.close()
        if stored_hash == propose_hash:
            # Exact replay: return byte-equivalent cached response
            return json.loads(stored_response_json)
        else:
            # Same evaluationId with changed content -> 409 Conflict
            raise HTTPException(status_code=409, detail="Evaluation ID already exists with different payload.")

    # Calculate inputDigest over dossiers
    input_digest = sha256_hex(canonical_json(dossiers))

    proposals: List[Dict[str, Any]] = []

    for dossier in dossiers:
        dossier_fp = sha256_hex(canonical_json(dossier))
        dossier_id = dossier.get("dossierId")

        # Check dossier cache
        cursor.execute(
            "SELECT call_id, action, target_json, payload_json, evidence_json FROM dossier_cache WHERE content_fingerprint = ?",
            (dossier_fp,),
        )
        cached = cursor.fetchone()
        if cached:
            call_id, action, target_json, payload_json, evidence_json = cached
            target = json.loads(target_json) if target_json else None
            item_payload = json.loads(payload_json)
            evidence = json.loads(evidence_json)
        else:
            action, target, item_payload, evidence = analyze_dossier(dossier, allowed_actions)
            # Deterministic, stable callId from content fingerprint (12-128 chars)
            call_id = f"call-{dossier_fp[:24]}"
            cursor.execute(
                """
                INSERT OR REPLACE INTO dossier_cache (
                    content_fingerprint, dossier_id, call_id, action, target_json, payload_json, evidence_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    dossier_fp,
                    dossier_id,
                    call_id,
                    action,
                    json.dumps(target) if target else None,
                    json.dumps(item_payload),
                    json.dumps(evidence),
                ),
            )

        valid_line_ids = [
            line.get("lineId")
            for src in dossier.get("sources", [])
            for line in src.get("lines", [])
            if line.get("lineId")
        ]
        filtered_evidence = [lid for lid in evidence if lid in valid_line_ids]
        if not filtered_evidence and valid_line_ids:
            filtered_evidence = [valid_line_ids[0]]

        proposals.append({
            "dossierId": dossier_id,
            "callId": call_id,
            "action": action,
            "target": target,
            "payload": item_payload,
            "evidence": sorted(list(set(filtered_evidence))),
        })

    response_data = {
        "profile": profile,
        "evaluationId": evaluation_id,
        "status": "awaiting_receipts",
        "inputDigest": input_digest,
        "proposals": proposals,
    }

    # Store evaluation state
    cursor.execute(
        """
        INSERT INTO evaluations (
            evaluation_id, propose_request_hash, propose_response_json, input_digest, receipt_verifier_json, proposals_json
        ) VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            evaluation_id,
            propose_hash,
            json.dumps(response_data),
            input_digest,
            json.dumps(verifier),
            json.dumps(proposals),
        ),
    )
    conn.commit()
    conn.close()

    return response_data


def handle_commit(payload: Dict[str, Any]) -> Dict[str, Any]:
    evaluation_id = payload.get("evaluationId")
    if not evaluation_id or not isinstance(evaluation_id, str):
        raise HTTPException(status_code=400, detail="Missing or invalid evaluationId.")

    receipts = payload.get("receipts")
    if not isinstance(receipts, list):
        raise HTTPException(status_code=400, detail="Missing or invalid receipts list.")

    input_digest = payload.get("inputDigest")
    profile = payload.get("profile", "ga5-mailroom-action-gate/v2")
    commit_hash = sha256_hex(canonical_json(payload))

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT propose_response_json, input_digest, receipt_verifier_json, proposals_json, commit_request_hash, commit_response_json
        FROM evaluations WHERE evaluation_id = ?
        """,
        (evaluation_id,),
    )
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=400, detail="Unknown evaluationId.")

    _, stored_input_digest, verifier_json, proposals_json, stored_commit_hash, stored_commit_response = row

    # Check for exact commit replay
    if stored_commit_response:
        conn.close()
        if stored_commit_hash == commit_hash:
            return json.loads(stored_commit_response)
        else:
            raise HTTPException(status_code=409, detail="Commit already completed with different payload.")

    # Input digest check
    if input_digest != stored_input_digest:
        conn.close()
        raise HTTPException(status_code=409, detail="Input digest mismatch.")

    verifier = json.loads(verifier_json)
    public_key_jwk = verifier.get("publicKeyJwk", {})
    stored_proposals = json.loads(proposals_json)
    proposal_map = {p["dossierId"]: p for p in stored_proposals}

    if len(receipts) != len(stored_proposals):
        conn.close()
        raise HTTPException(status_code=400, detail="Receipt count does not match proposals count.")

    # Track seen receipts to prevent duplicates
    seen_receipt_ids: Set[str] = set()
    seen_dossiers: Set[str] = set()
    outcomes: List[Dict[str, Any]] = []

    # Atomic validation: verify EVERY receipt before executing any action
    for receipt in receipts:
        if not isinstance(receipt, dict):
            conn.close()
            raise HTTPException(status_code=400, detail="Invalid receipt item.")

        dossier_id = receipt.get("dossierId")
        call_id = receipt.get("callId")
        receipt_id = receipt.get("receiptId")
        signature = receipt.get("receiptSignature")
        action = receipt.get("action")
        p_digest = receipt.get("proposalDigest")

        if not dossier_id or not call_id or not receipt_id or not signature:
            conn.close()
            raise HTTPException(status_code=400, detail="Receipt missing required fields.")

        if receipt_id in seen_receipt_ids:
            conn.close()
            raise HTTPException(status_code=400, detail=f"Duplicate receiptId: {receipt_id}")
        seen_receipt_ids.add(receipt_id)

        if dossier_id in seen_dossiers:
            conn.close()
            raise HTTPException(status_code=400, detail=f"Duplicate receipt for dossier: {dossier_id}")
        seen_dossiers.add(dossier_id)

        proposal = proposal_map.get(dossier_id)
        if not proposal:
            conn.close()
            raise HTTPException(status_code=400, detail=f"Unknown dossierId in receipt: {dossier_id}")

        if call_id != proposal.get("callId"):
            conn.close()
            raise HTTPException(status_code=400, detail=f"Receipt callId mismatch for {dossier_id}")

        if action != proposal.get("action"):
            conn.close()
            raise HTTPException(status_code=400, detail=f"Receipt action mismatch for {dossier_id}")

        expected_digest = proposal_digest_for(proposal)
        if p_digest != expected_digest:
            conn.close()
            raise HTTPException(status_code=400, detail=f"Receipt proposalDigest mismatch for {dossier_id}")

        # Construct signed object: every receipt field except receiptSignature
        inner_receipt = {k: v for k, v in receipt.items() if k != "receiptSignature"}
        signed_object = {
            "profile": profile,
            "evaluationId": evaluation_id,
            "inputDigest": input_digest,
            "receipt": inner_receipt,
        }

        # Verify signature
        if not verify_ed25519_signature(public_key_jwk, signed_object, signature):
            conn.close()
            raise HTTPException(status_code=400, detail=f"Invalid receiptSignature for {dossier_id}")

        # Record outcome
        accepted = bool(receipt.get("accepted", False))
        outcomes.append({
            "dossierId": dossier_id,
            "callId": call_id,
            "action": action,
            "proposalDigest": expected_digest,
            "receiptId": receipt_id,
            "status": "executed" if accepted else "rejected",
        })

    response_data = {
        "profile": profile,
        "evaluationId": evaluation_id,
        "status": "completed",
        "inputDigest": input_digest,
        "outcomes": outcomes,
    }

    # Persist commit response
    cursor.execute(
        """
        UPDATE evaluations
        SET commit_request_hash = ?, commit_response_json = ?
        WHERE evaluation_id = ?
        """,
        (commit_hash, json.dumps(response_data), evaluation_id),
    )
    conn.commit()
    conn.close()

    return response_data


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)
