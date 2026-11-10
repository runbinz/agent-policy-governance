"""Exercise the local API and worker; standard-library only, no real payments."""
import copy
import json
import os
import time
import urllib.error
import urllib.request
import uuid

BASE = os.getenv("APL_DEMO_BASE_URL", "http://127.0.0.1:8080")
A = os.getenv("APL_DEV_TOKEN_A", "local-tenant-a-token-at-least-32-bytes")
B = os.getenv("APL_DEV_TOKEN_B", "local-tenant-b-token-at-least-32-bytes")
REVIEWER = os.getenv("APL_DEV_REVIEWER_TOKEN", "local-reviewer-token-at-least-32-bytes")


def call(method, path, token=A, body=None, key=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    if key:
        headers["Idempotency-Key"] = key
    request = urllib.request.Request(BASE + path, headers=headers, method=method,
                                     data=json.dumps(body).encode() if body else None)
    try:
        response = urllib.request.urlopen(request, timeout=5)
    except urllib.error.HTTPError as error:
        response = error
    raw = response.read()
    return response.status, json.loads(raw) if raw else None


def wait_for_status(action_id, expected):
    for _ in range(100):
        code, action = call("GET", "/v1/actions/" + action_id)
        assert code == 200, (code, action)
        if action["status"] == expected:
            return action
        time.sleep(0.1)
    raise AssertionError(f"Expected {expected}; last status was {action['status']}")


request = {"type": "refund.create", "connection_id": "00000000-0000-0000-0000-000000000301",
           "resource": {"payment_id": "fake_demo_payment"},
           "parameters": {"amount_minor": 2500, "currency": "USD"}}
assert call("GET", "/v1/actions/" + str(uuid.uuid4()), token=None)[0] == 401
key = str(uuid.uuid4())
code, action = call("POST", "/v1/actions", body=request, key=key)
assert code == 202, (code, action)
action_id = action["id"]
assert action["status_url"] == "/v1/actions/" + action_id
assert call("POST", "/v1/actions", body=request, key=key)[1]["id"] == action_id
changed = copy.deepcopy(request)
changed["parameters"]["amount_minor"] += 1
assert call("POST", "/v1/actions", body=changed, key=key)[0] == 409
assert call("POST", "/v1/actions", token=B, body=request, key=str(uuid.uuid4()))[0] == 404
assert call("GET", "/v1/actions/" + action_id, token=B)[0] == 404
assert call("GET", "/v1/actions/" + action_id + "/events", token=B)[0] == 404
wait_for_status(action_id, "succeeded")
code, events = call("GET", "/v1/actions/" + action_id + "/events")
assert code == 200 and len(events) >= 2, (code, events)
changed["parameters"]["amount_minor"] = 5001
code, pending = call("POST", "/v1/actions", body=changed, key=str(uuid.uuid4()))
assert code == 202, (code, pending)
pending_id = pending["id"]
wait_for_status(pending_id, "pending_approval")
assert call("GET", "/v1/approvals")[0] == 401
assert call("GET", "/v1/actions/" + pending_id, token=REVIEWER)[0] == 401
code, queue = call("GET", "/v1/approvals", token=REVIEWER)
assert code == 200, (code, queue)
approval = next(item for item in queue if item["action_id"] == pending_id)
decision = {"generation": approval["generation"], "action_digest": approval["action_digest"], "decision": "approve"}
path = "/v1/approvals/" + pending_id + "/decision"
wrong_digest = "0" * 64 if decision["action_digest"] != "0" * 64 else "1" * 64
assert call("POST", path, token=REVIEWER, body={**decision, "action_digest": wrong_digest})[0] == 409
assert call("POST", path, token=REVIEWER, body=decision)[0] == 200
assert call("POST", path, token=REVIEWER, body=decision)[0] == 409
wait_for_status(pending_id, "succeeded")
assert call("POST", "/v1/actions/" + pending_id + "/cancel")[0] == 409
code, cancel_target = call("POST", "/v1/actions", body=changed, key=str(uuid.uuid4()))
assert code == 202, (code, cancel_target)
cancel_id = cancel_target["id"]
wait_for_status(cancel_id, "pending_approval")
cancel_path = "/v1/actions/" + cancel_id + "/cancel"
assert call("POST", cancel_path, token=B)[0] == 404
code, cancelled = call("POST", cancel_path)
assert code == 200 and cancelled["status"] == "cancelled", (code, cancelled)
print("PASS: authentication, idempotency, isolation, audit, exact approval, replay protection, cancellation, fake execution")
print("Actions:", action_id, pending_id)
