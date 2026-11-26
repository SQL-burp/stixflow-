from stixflow.patterns import Observable, extract_observables


def test_single_ipv4():
    assert extract_observables("[ipv4-addr:value = '203.0.113.45']") == [Observable("ipv4", "203.0.113.45")]


def test_compound_or_pattern():
    obs = extract_observables("[ipv4-addr:value = '203.0.113.46' OR domain-name:value = 'EVIL.Example']")
    assert Observable("ipv4", "203.0.113.46") in obs
    assert Observable("domain", "evil.example") in obs  # domains are lower-cased


def test_file_hash_keeps_algorithm():
    h = "A" * 64
    (obs,) = extract_observables(f"[file:hashes.'SHA-256' = '{h}']")
    assert obs.ioc_type == "hash" and obs.value == h.lower() and obs.detail == "SHA-256"


def test_cidr_is_normalized():
    (obs,) = extract_observables("[ipv4-addr:value = '198.51.100.7/24']")
    assert obs.value == "198.51.100.0/24"


def test_non_equality_operators_are_ignored():
    assert extract_observables("[domain-name:value LIKE '%.example']") == []
    assert extract_observables("[ipv4-addr:value != '192.0.2.1']") == []


def test_unknown_object_paths_are_ignored():
    assert extract_observables("[network-traffic:dst_port = '502']") == []


def test_url_and_email():
    obs = extract_observables(
        "[url:value = 'http://update-plcsync.example/fw/patch.bin'] AND [email-addr:value = 'a@b.example']"
    )
    assert {o.ioc_type for o in obs} == {"url", "email"}


def test_duplicates_collapsed():
    assert len(extract_observables("[ipv4-addr:value = '192.0.2.1' OR ipv4-addr:value = '192.0.2.1']")) == 1
