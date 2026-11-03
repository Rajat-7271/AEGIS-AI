from app.investigator.recon_agent import _validated_recon_iocs


def test_rejects_hostname_mislabeled_as_ip_and_bracketed_id_as_domain():
    assert _validated_recon_iocs([
        {"type": "ip", "value": "WIN-FIN-01"},
        {"type": "domain", "value": "[8cf7311bc4d5]"},
    ]) == []


def test_rejects_executable_names_as_domains():
    assert _validated_recon_iocs([
        {"type": "domain", "value": "winword.exe"},
        {"type": "domain", "value": "powershell.exe"},
    ]) == []


def test_accepts_valid_iocs():
    results = _validated_recon_iocs([
        {"type": "ip", "value": "8.8.8.8"},
        {"type": "domain", "value": "example.com"},
        {"type": "url", "value": "https://example.com/path"},
        {"type": "hash", "value": "a" * 32},
        {"type": "hash", "value": "b" * 40},
        {"type": "hash", "value": "c" * 64},
    ])
    assert len(results) == 6


def test_rejects_short_hex_identifier_as_hash():
    assert _validated_recon_iocs([
        {"type": "hash", "value": "8cf7311bc4d5"},
    ]) == []


def test_deduplicates_same_type_and_value_case_insensitively():
    results = _validated_recon_iocs([
        {"type": "domain", "value": "Example.com"},
        {"type": "domain", "value": "example.com"},
    ])
    assert len(results) == 1
