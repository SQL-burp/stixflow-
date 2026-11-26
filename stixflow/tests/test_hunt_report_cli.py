from pathlib import Path

from conftest import ICS_BUNDLE, IT_BUNDLE
from stixflow.cli import main
from stixflow.export import to_blocklist, to_csv
from stixflow.hunt import Hunter, extract_candidates
from stixflow.report import build_report

SAMPLE_LOG = Path(__file__).resolve().parents[1] / "samples" / "plant_firewall.log"


def test_refang_and_extract():
    c = extract_candidates("beacon to hxxp://update-plcsync[.]example/fw/patch.bin from 10.0.0.1")
    assert "http://update-plcsync.example/fw/patch.bin" in c
    assert "update-plcsync.example" in c and "10.0.0.1" in c


def test_hunt_sample_log(loaded_store):
    hits = Hunter(loaded_store).hunt_file(SAMPLE_LOG)
    observed = {h.observed for h in hits}
    assert "203.0.113.45" in observed  # exact IP
    assert "198.51.100.17" in observed  # CIDR containment
    assert "ap-billing@invoice-portal.example" in observed  # defanged email
    assert any(h.ioc_type == "hash" for h in hits)
    assert "192.0.2.200" not in observed  # revoked indicator must not alert
    c2 = next(h for h in hits if h.observed == "203.0.113.45")
    assert "intrusion-set: COPPER LATHE" in c2.context


def test_hunt_no_false_positive_on_internal_traffic(loaded_store):
    assert Hunter(loaded_store).hunt_lines(["ALLOW 10.40.1.15 10.40.2.21 502 tcp modbus"]) == []


def test_report_sections(loaded_store):
    md = build_report(loaded_store)
    for heading in ("## Collection summary", "## Adversary activity", "## ATT&CK techniques",
                    "## Indicators of compromise", "```mermaid"):
        assert heading in md
    assert "T0836" in md and "M0937" in md


def test_exports(loaded_store):
    csv_text = to_csv(loaded_store)
    assert csv_text.splitlines()[0].startswith("ioc_type,value")
    block = to_blocklist(loaded_store).split()
    assert "update-plcsync.example" in block and "192.0.2.200" not in block


def test_cli_end_to_end(tmp_path, capsys):
    db = str(tmp_path / "cli.db")
    assert main(["--db", db, "import", str(ICS_BUNDLE), str(IT_BUNDLE)]) == 0
    assert main(["--db", db, "hunt", str(SAMPLE_LOG), "--fail-on-hit"]) == 3
    out = tmp_path / "iocs.csv"
    assert main(["--db", db, "export", "-f", "csv", "-o", str(out)]) == 0
    assert "203.0.113.45" in out.read_text()
    assert main(["--db", db, "pivot", "PRESSBREAK"]) == 0
