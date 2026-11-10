"""Local-browser trust boundary checks using real ML-DSA identities."""

from __future__ import annotations

import ast
import base64
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from client.app import create_app
from protocol.identity import Identity, b64


@pytest.fixture
def local_client(tmp_path, monkeypatch):
    monkeypatch.setenv("CRYTOSAGE_REPORT_DIR", str(tmp_path / "reports"))
    bob = Identity(tmp_path / "Bob", "Bob")
    contacts = tmp_path / "contacts"
    contacts.mkdir(mode=0o700)
    (contacts / "Bob.json").write_text(
        json.dumps({"name": "Bob", "public": b64(bob.public)})
    )
    app = create_app("Alice", 8001, tmp_path / "Alice", contacts)
    # No context-manager lifespan: these boundary tests must not contact a relay.
    client = TestClient(app, base_url="http://127.0.0.1:8001")
    yield client, app.state.client, bob, tmp_path
    client.close()


def auth(client):
    response = client.get("/api/state")
    assert response.status_code == 200
    return {
        "X-CSRF-Token": response.json()["csrf_token"],
        "Origin": "http://127.0.0.1:8001",
    }


@pytest.mark.parametrize("host", ["127.0.0.1:8001", "localhost:8001"])
def test_exact_loopback_hosts_are_accepted(local_client, host):
    client, _, _, _ = local_client
    assert client.get("/api/state", headers={"Host": host}).status_code == 200


@pytest.mark.parametrize(
    "host",
    [
        "evil.example:8001",
        "127.0.0.1.evil.example:8001",
        "localhost.evil.example:8001",
        "127.0.0.1:8002",
        "127.0.0.1",
        "0.0.0.0:8001",
    ],
)
def test_dns_rebinding_or_wrong_port_host_is_rejected(local_client, host):
    client, _, _, _ = local_client
    response = client.get("/api/state", headers={"Host": host})
    assert response.status_code == 403
    assert "csrf_token" not in response.text


@pytest.mark.parametrize(
    "origin",
    [
        "https://evil.example",
        "http://localhost:8002",
        "http://127.0.0.1.evil.example:8001",
        "null",
    ],
)
def test_untrusted_origin_cannot_read_state_or_change_trust(local_client, origin):
    client, _, bob, _ = local_client
    headers = auth(client)
    headers["Origin"] = origin
    assert client.get("/api/state", headers=headers).status_code == 403
    response = client.post(
        "/api/trust",
        json={"peer": "Bob", "fingerprint": bob.fingerprint},
        headers=headers,
    )
    assert response.status_code == 403


@pytest.mark.parametrize("site", ["cross-site", "same-site"])
def test_cross_origin_fetch_metadata_is_rejected_even_with_token(local_client, site):
    client, _, bob, _ = local_client
    headers = {**auth(client), "Sec-Fetch-Site": site}
    assert client.get("/api/state", headers=headers).status_code == 403
    response = client.post(
        "/api/trust",
        json={"peer": "Bob", "fingerprint": bob.fingerprint},
        headers=headers,
    )
    assert response.status_code == 403


def test_same_origin_fetch_can_pin_verified_contact(local_client):
    client, local, bob, folder = local_client
    headers = {**auth(client), "Sec-Fetch-Site": "same-origin"}
    response = client.post(
        "/api/trust", json={"peer": "Bob", "fingerprint": "0" * 64}, headers=headers
    )
    assert response.status_code == 400
    assert "Fingerprint" in response.json()["detail"]
    assert not local.identity.trusted
    response = client.post(
        "/api/trust",
        json={"peer": "Bob", "fingerprint": bob.fingerprint},
        headers=headers,
    )
    assert response.status_code == 200
    assert local.identity.trusted == {"Bob": bob.fingerprint}
    assert json.loads((folder / "Alice" / "trust.json").read_text()) == {
        "Bob": bob.fingerprint
    }
    assert client.get("/api/state").json()["contacts"][0]["verified"] is True


@pytest.mark.parametrize("token", [None, "", "wrong-token"])
def test_csrf_token_is_required_for_mutations(local_client, token):
    client, local, bob, _ = local_client
    headers = {} if token is None else {"X-CSRF-Token": token}
    response = client.post(
        "/api/trust",
        json={"peer": "Bob", "fingerprint": bob.fingerprint},
        headers=headers,
    )
    assert response.status_code == 403
    assert not local.identity.trusted


def test_json_content_type_required(local_client):
    client, local, _, _ = local_client
    headers = {**auth(client), "Content-Type": "text/plain"}
    response = client.post("/api/trust", content='{"peer":"Bob"}', headers=headers)
    assert response.status_code == 415
    assert not local.identity.trusted


@pytest.mark.parametrize(
    "body",
    [
        {"text": 123},
        {"text": []},
        {"text": ""},
        {"text": "hello", "override_policy": True},
        {"text": "x" * 16385},
    ],
)
def test_message_schema_is_strict_and_size_limited(local_client, body):
    client, local, _, _ = local_client
    response = client.post("/api/message", json=body, headers=auth(client))
    assert response.status_code == 422
    assert not local.messages


def test_total_request_size_is_bounded(local_client):
    client, local, _, _ = local_client
    response = client.post(
        "/api/message", json={"text": "x" * 65536}, headers=auth(client)
    )
    assert response.status_code == 413
    assert not local.messages


def test_request_size_checks_actual_body_not_only_declared_length(local_client):
    client, local, _, _ = local_client
    response = client.post(
        "/api/message",
        json={"text": "x" * 65536},
        headers={**auth(client), "Content-Length": "1"},
    )
    assert response.status_code == 413
    assert not local.messages


@pytest.mark.parametrize("content_length", ["not-a-number", "-1"])
def test_malformed_content_length_is_rejected_safely(local_client, content_length):
    client, local, _, _ = local_client
    response = client.post(
        "/api/message",
        json={"text": "hello"},
        headers={**auth(client), "Content-Length": content_length},
    )
    assert response.status_code == 400
    assert not local.messages


@pytest.mark.parametrize("trials", ["10", True, 1, 1001])
def test_benchmark_schema_rejects_coercion_and_excess_work(local_client, trials):
    client, local, _, _ = local_client
    response = client.post(
        "/api/benchmark", json={"trials": trials}, headers=auth(client)
    )
    assert response.status_code == 422
    assert not local.benchmark_busy


def test_static_ui_has_restrictive_csp_and_no_cache(local_client):
    client, _, _, _ = local_client
    response = client.get("/")
    assert response.status_code == 200
    csp = response.headers["Content-Security-Policy"]
    for directive in (
        "default-src 'self'",
        "script-src 'self'",
        "frame-ancestors 'none'",
        "base-uri 'none'",
    ):
        assert directive in csp
    assert "'unsafe-inline'" not in csp and "'unsafe-eval'" not in csp
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"


def test_state_exposes_public_information_without_key_material(local_client):
    client, local, _, folder = local_client
    response = client.get("/api/state")
    assert response.status_code == 200
    state = response.json()
    assert (
        state["identity"]["name"] == "Alice"
        and state["identity"]["fingerprint"] == local.identity.fingerprint
    )
    assert state["session"] is None and state["connected"] is False
    identity_file = (folder / "Alice" / "identity.json").read_text()
    assert base64.b64encode(local.identity._secret).decode() not in identity_file
    assert base64.b64encode(local.identity._secret).decode() not in response.text
    forbidden = {
        "secret",
        "private_key",
        "shared_secret",
        "root_key",
        "message_key",
        "send_chain",
        "recv_chain",
        "secret_key",
        "_secret",
    }

    def check(value):
        if isinstance(value, dict):
            assert not forbidden.intersection(value)
            for item in value.values():
                check(item)
        elif isinstance(value, list):
            for item in value:
                check(item)

    check(state)


def test_relay_dependency_graph_has_no_private_crypto_operations():
    """A server attack helper must not pull cryptographic clients into the relay."""
    root = Path(__file__).resolve().parents[1]
    visited = set()
    queue = ["server.relay"]
    forbidden_roots = {"crypto", "protocol", "client"}
    forbidden_calls = {
        "sign",
        "signature_keypair",
        "kem_keypair",
        "decapsulate",
        "decrypt",
        "hkdf",
        "encrypt",
        "Identity",
        "Peer",
    }
    while queue:
        module = queue.pop()
        if module in visited:
            continue
        visited.add(module)
        source = root.joinpath(*module.split(".")).with_suffix(".py")
        assert source.is_file(), f"Missing relay dependency: {module}"
        tree = ast.parse(source.read_text(), filename=str(source))
        for node in ast.walk(tree):
            imports = []
            if isinstance(node, ast.Import):
                imports = [item.name for item in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports = [node.module]
            for imported in imports:
                public_registration = (
                    module == "server.relay"
                    and isinstance(node, ast.ImportFrom)
                    and {alias.name for alias in node.names}
                    <= {
                        "crypto.primitives": {"verify"},
                        "protocol.identity": {
                            "b64",
                            "unb64",
                            "fingerprint",
                            "valid_name",
                        },
                        "protocol.registration": {"registration_payload"},
                    }.get(imported, set())
                )
                assert (
                    public_registration or imported.split(".")[0] not in forbidden_roots
                ), f"{module} imports {imported}"
                if imported.split(".")[0] in {"server", "attacks"}:
                    queue.append(imported)
            if isinstance(node, ast.Call):
                called = (
                    node.func.id
                    if isinstance(node.func, ast.Name)
                    else (
                        node.func.attr if isinstance(node.func, ast.Attribute) else ""
                    )
                )
                assert called not in forbidden_calls, (
                    f"{module} calls private operation {called}"
                )


@pytest.mark.parametrize(
    "value",
    [
        "ws://127.0.0.1:8765@evil.example:80",
        "ws://evil.example:8765",
        "wss://127.0.0.1:8765",
        "ws://127.0.0.1:invalid",
        "ws://127.0.0.1:8765?redirect=evil",
    ],
)
def test_relay_url_parser_rejects_non_loopback_routes(value):
    from client.app import local_relay_url

    assert not local_relay_url(value)


def test_relay_url_parser_accepts_loopback():
    from client.app import local_relay_url

    assert local_relay_url("ws://127.0.0.1:8765")


def test_policy_manager_saves_for_future_sessions_and_requires_confirmation(
    local_client,
):
    client, local, _, _ = local_client
    import copy

    original = copy.deepcopy(client.get("/api/policy").json()["policy"])
    updated = copy.deepcopy(original)
    updated["allow_experimental"] = True
    refused = client.post(
        "/api/policy",
        json={"policy": updated, "confirm_restrictions": False},
        headers=auth(client),
    )
    assert refused.status_code == 400
    assert local.peer.policy == original
    accepted = client.post(
        "/api/policy",
        json={"policy": updated, "confirm_restrictions": True},
        headers=auth(client),
    )
    assert accepted.status_code == 200
    assert accepted.json()["pending_effect"] == "new_sessions_only"
    assert local.peer.policy["allow_experimental"] is True
    reset = client.post("/api/policy/reset", json={}, headers=auth(client))
    assert reset.status_code == 200
    assert not local.peer.policy["allow_experimental"]


def test_reset_cannot_relax_policy_without_confirmation(local_client):
    client, local, _, _ = local_client
    import copy

    stronger = copy.deepcopy(local.peer.policy)
    stronger["minimum_security_level"] = 5
    response = client.post(
        "/api/policy",
        json={"policy": stronger, "confirm_restrictions": False},
        headers=auth(client),
    )
    assert response.status_code == 200
    denied = client.post("/api/policy/reset", json={}, headers=auth(client))
    assert denied.status_code == 400
    assert local.peer.policy["minimum_security_level"] == 5
    accepted = client.post(
        "/api/policy/reset", json={"confirm_restrictions": True}, headers=auth(client)
    )
    assert accepted.status_code == 200
    assert local.peer.policy["minimum_security_level"] == 3


def test_chunked_mutation_is_bounded_before_handler(local_client):
    client, local, _, _ = local_client
    response = client.post(
        "/api/message",
        headers={**auth(client), "Content-Type": "application/json"},
        content=iter([b"x" * 40_000, b"x" * 40_000]),
    )
    assert response.status_code == 413
    assert not local.messages


def test_validation_error_does_not_echo_message_payload(local_client):
    client, _, _, _ = local_client
    private = "This text must not appear in validation reports"
    response = client.post("/api/message", json={"text": private}, headers=auth(client))
    assert response.status_code == 422
    assert private not in response.text


def test_retry_and_rekey_without_an_authenticated_session(local_client):
    client, local, _, _ = local_client
    headers = auth(client)
    retry = client.post("/api/message/unknown/retry", json={}, headers=headers)
    rekey = client.post("/api/rekey", json={}, headers=headers)
    assert retry.status_code == rekey.status_code == 400
    assert "authenticate" in retry.json()["detail"]
    assert "No session" in rekey.json()["detail"]
    assert not local.messages


def test_invalid_benchmark_profile_is_rejected(local_client):
    client, local, _, _ = local_client
    response = client.post(
        "/api/benchmark", json={"profile": "wan"}, headers=auth(client)
    )
    assert response.status_code == 422
    assert not local.benchmark_busy


def test_security_lab_returns_observed_attack_and_unavailable_report(local_client):
    client, local, _, _ = local_client
    assert client.get("/api/attacks").status_code == 200
    assert client.get("/api/export/security.html").status_code == 404
    headers = auth(client)
    invalid = client.post("/api/attack", json={"scenario": "unknown"}, headers=headers)
    assert invalid.status_code == 400
    attack = client.post("/api/attack", json={"scenario": "tamper"}, headers=headers)
    assert attack.status_code == 200
    assert attack.json()["status"] == "blocked"
    assert attack.json()["validation"] == "AES-256-GCM authentication"
    report = client.get("/api/report").json()
    assert report["test_report_status"] == "not_run"
    assert report["prototype"] is True and report["attacks"] == local.attack_results


def test_benchmark_api_records_and_exports_real_results(local_client):
    client, local, _, _ = local_client
    assert client.get("/api/benchmarks").json()["status"] == "not_run"
    headers = auth(client)
    conflict = client.post(
        "/api/benchmark", json={"profile": "localhost", "delay_ms": 4}, headers=headers
    )
    assert conflict.status_code == 400 and not local.benchmark_busy
    result = client.post(
        "/api/benchmark", json={"profile": "localhost", "trials": 2}, headers=headers
    )
    assert result.status_code == 200 and not local.benchmark_busy
    data = result.json()
    assert data["metadata"]["configuration"]["network_profile"] == "localhost"
    assert {item["name"] for item in data["algorithms"]} == {"HQC-3", "ML-KEM-768"}
    assert all(
        item["statistics"]["network_handshake_ms"]["n"] == 2
        for item in data["algorithms"]
    )
    assert client.get("/api/benchmarks").json() == data
    assert client.get("/api/export/benchmarks.json").json() == data
    assert client.get("/api/export/benchmarks.zip").status_code == 200


def test_public_contact_card_json_and_qr_export(local_client):
    client, local, _, _ = local_client
    response = client.get("/api/contact-card.json")
    assert response.status_code == 200
    assert response.json() == {
        "name": "Alice",
        "public": b64(local.identity.public),
        "fingerprint": local.identity.fingerprint,
    }
    assert response.headers["content-disposition"].startswith("attachment")
    response = client.get("/api/contact-card.svg")
    assert response.status_code == 200
    assert response.headers["content-type"] == "image/svg+xml"
    assert b"<svg" in response.content and b"<path" in response.content


def test_contact_card_import_rejects_bad_fingerprint_and_never_pins(local_client):
    client, local, bob, tmp_path = local_client
    card = {"name": "Robert", "public": b64(bob.public), "fingerprint": bob.fingerprint}
    path = tmp_path / "contacts" / "Robert.json"
    assert client.post("/api/contacts", json=card).status_code == 403
    assert (
        client.post(
            "/api/contacts",
            json={**card, "fingerprint": "a" * 64},
            headers=auth(client),
        ).status_code
        == 400
    )
    assert not path.exists()
    assert (
        client.post("/api/contacts", json=card, headers=auth(client)).status_code == 200
    )
    assert path.stat().st_mode & 0o077 == 0
    assert "Robert" not in local.identity.trusted
    assert not next(row for row in local.contacts() if row["name"] == "Robert")[
        "verified"
    ]
    assert (
        client.post(
            "/api/trust",
            json={"peer": "Robert", "fingerprint": bob.fingerprint},
            headers=auth(client),
        ).status_code
        == 200
    )
    assert local.identity.trusted["Robert"] == bob.fingerprint


@pytest.mark.parametrize("address", ["192.168.1.4", "10.2.3.4", "172.16.31.42"])
def test_lan_client_relay_requires_opt_in(address):
    from client.app import local_relay_url

    url = f"ws://{address}:8765"
    assert not local_relay_url(url)
    assert local_relay_url(url, lan=True)
    assert not local_relay_url("ws://8.8.8.8:8765", lan=True)
    assert not local_relay_url(f"ws://user@{address}:8765", lan=True)
