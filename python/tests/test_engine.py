"""Compatibility is checked for plain requests too, before the daemon sees a URL."""
import json
import pytest
import tlsforge

@pytest.mark.parametrize("major", ["missing", "null", "0", "1", "2", "3", "4", "5", "7", "-1", "1.5", '"1"', "true"])
def test_every_request_requires_exact_engine_before_url_or_cookies(client, monkeypatch, tmp_path, major):
    log = tmp_path / "received.jsonl"
    monkeypatch.setenv("TLSFORGE_TEST_ENGINE_MAJOR", major)
    monkeypatch.setenv("TLSFORGE_TEST_WIRE_LOG", str(log))
    c = client()
    for context in [None, {"kind": "navigation"}]:
        with pytest.raises(tlsforge.Unsupported, match="engine_major .*SDK engine major 6; request was not sent"):
            c.get("https://must-not-resolve.invalid/", cookies=["secret=never-sent"], browser_context=context)
    received = [json.loads(line) for line in log.read_text().splitlines()]
    assert len(received) == 1
    assert received[0]["control"] == "hello"
    assert "url" not in received[0] and "setCookie" not in received[0]

@pytest.mark.parametrize("mode", ["1", "fixture-old"])
def test_legacy_daemon_cannot_receive_even_plain_request(client, monkeypatch, mode):
    monkeypatch.setenv("TLSFORGE_TEST_PROTOCOL", mode)
    with pytest.raises(tlsforge.Unsupported, match="SDK engine major 6"):
        client().get("https://must-not-resolve.invalid/")

@pytest.mark.parametrize("version", ["0.1.0", "1.0.0", "bad"])
def test_inconsistent_daemon_version_is_rejected(client, monkeypatch, version):
    monkeypatch.setenv("TLSFORGE_TEST_ENGINE_VERSION", version)
    with pytest.raises(tlsforge.Unsupported):
        client().get("https://must-not-resolve.invalid/")

def test_compatible_plain_request_declares_major(client):
    answer = client().get("https://ok/").json()
    assert "engine_major" in answer["sent"] and answer["controls"] == 1

def test_replacement_process_must_pass_own_engine_handshake(client, monkeypatch, tmp_path):
    log = tmp_path / "replacement.jsonl"
    monkeypatch.setenv("TLSFORGE_TEST_WIRE_LOG", str(log))
    monkeypatch.setenv("TLSFORGE_TEST_ENGINE_MAJOR", "6")
    c = client(timeout=0.5)
    c.get("https://ok/first")
    monkeypatch.setenv("TLSFORGE_TEST_ENGINE_MAJOR", "0")
    with pytest.raises(tlsforge.Timeout):
        c.get("https://silent/")
    with pytest.raises(tlsforge.Unsupported):
        c.get("https://must-not-resolve.invalid/")
    received = [json.loads(line) for line in log.read_text().splitlines()]
    assert sum(line.get("control") == "hello" for line in received) == 2
    assert not any("must-not-resolve" in line.get("url", "") for line in received)
