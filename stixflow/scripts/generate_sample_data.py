"""Generate the sample STIX 2.1 bundles served by the demo TAXII server.

The scenario is FICTIONAL and built for demos/tests:
  * intrusion set COPPER LATHE targets discrete manufacturing (stamping / press lines)
  * PRESSBREAK malware tampers with servo-press parameters and vision-inspection recipes
  * LOCKSTEP is commodity ransomware that reaches plants through IT

All network indicators use documentation ranges (RFC 5737: 192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24) and the reserved .example TLD. Hashes are
SHA-256 digests of throwaway strings. ATT&CK technique / mitigation IDs are real
public identifiers so the report output maps to the framework analysts use.

Run:  python scripts/generate_sample_data.py
"""

from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path

NS = uuid.UUID("0b6c3e8e-6d3a-4a51-a6a1-1c2f0f9c4d21")
OUT = Path(__file__).resolve().parents[1] / "src" / "stixflow" / "data"
TLP_CLEAR = "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"  # TLP:WHITE/CLEAR (STIX 2.1 predefined)
T0 = "2026-09-14T13:00:00.000Z"
T1 = "2026-10-02T09:30:00.000Z"


def sid(stix_type: str, key: str) -> str:
    return f"{stix_type}--{uuid.uuid5(NS, stix_type + ':' + key)}"


def fake_sha256(label: str) -> str:
    return hashlib.sha256(f"stixflow-sample:{label}".encode()).hexdigest()


PRODUCER = {
    "type": "identity",
    "spec_version": "2.1",
    "id": sid("identity", "producer"),
    "created": T0,
    "modified": T0,
    "name": "stixflow Sample Feed",
    "identity_class": "organization",
    "description": "Fictional producer used for stixflow demos and tests.",
}


def base(stix_type: str, key: str, name: str | None = None, modified: str = T0, **kw) -> dict:
    obj = {
        "type": stix_type,
        "spec_version": "2.1",
        "id": sid(stix_type, key),
        "created": T0,
        "modified": modified,
        "created_by_ref": PRODUCER["id"],
        "object_marking_refs": [TLP_CLEAR],
    }
    if name:
        obj["name"] = name
    obj.update(kw)
    return obj


def attack_pattern(tid: str, name: str, domain: str = "ics-attack") -> dict:
    return base(
        "attack-pattern",
        tid,
        name,
        external_references=[
            {
                "source_name": "mitre-attack" if domain == "enterprise-attack" else "mitre-ics-attack",
                "external_id": tid,
                "url": f"https://attack.mitre.org/techniques/{tid}/",
            }
        ],
    )


def coa(mid: str, name: str, desc: str) -> dict:
    return base(
        "course-of-action",
        mid,
        name,
        description=desc,
        external_references=[
            {"source_name": "mitre-ics-attack", "external_id": mid, "url": f"https://attack.mitre.org/mitigations/{mid}/"}
        ],
    )


def indicator(key: str, name: str, pattern: str, desc: str = "", modified: str = T0, **kw) -> dict:
    return base(
        "indicator",
        key,
        name,
        modified=modified,
        description=desc,
        indicator_types=kw.pop("indicator_types", ["malicious-activity"]),
        pattern=pattern,
        pattern_type="stix",
        valid_from=T0,
        **kw,
    )


def rel(src: dict, rtype: str, tgt: dict) -> dict:
    return base(
        "relationship",
        f"{src['id']}|{rtype}|{tgt['id']}",
        relationship_type=rtype,
        source_ref=src["id"],
        target_ref=tgt["id"],
    )


def bundle(objects: list[dict], title: str, description: str) -> dict:
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid5(NS, title)}",
        "x_stixflow_title": title,
        "x_stixflow_description": description,
        "objects": objects,
    }


def ics_bundle() -> dict:
    sector = base("identity", "sector-mfg", "Discrete Manufacturing (Metal Stamping)",
                  identity_class="class", sectors=["manufacturing"])
    actor = base("threat-actor", "copper-lathe-actor", "COPPER LATHE Operators",
                 threat_actor_types=["crime-syndicate"], sophistication="advanced",
                 resource_level="organization", primary_motivation="personal-gain",
                 description="Fictional group extorting manufacturers by threatening production quality.")
    iset = base("intrusion-set", "copper-lathe", "COPPER LATHE",
                aliases=["CL-01"], first_seen="2026-06-01T00:00:00Z",
                goals=["Disrupt press-line output", "Silently degrade part quality to support extortion"],
                description="Fictional intrusion set targeting stamping plants via exposed remote-access gear.")
    campaign = base("campaign", "quiet-tonnage", "Operation QUIET TONNAGE",
                    first_seen="2026-08-15T00:00:00Z",
                    objective="Gain persistent access to press-line PLCs and HMI engineering workstations.")
    malware = base("malware", "pressbreak", "PRESSBREAK", is_family=True,
                   malware_types=["backdoor", "remote-access-trojan"],
                   capabilities=["communicates-with-c2", "evades-av"],
                   description="Fictional ICS framework. Modules push altered servo-press tonnage/stroke "
                               "parameters over Modbus/TCP and swap machine-vision inspection recipes so "
                               "out-of-tolerance parts pass inspection.")
    scanner = base("tool", "gridsweep", "GRIDSWEEP", tool_types=["network-capture"],
                   description="Fictional scanner enumerating Modbus/TCP (502) and EtherNet/IP (44818) devices.")
    vuln = base("vulnerability", "hmi-auth-bypass", "SAMPLE-2026-0001 HMI web auth bypass",
                description="Fictional auth bypass in an HMI web server, used for initial access.")

    aps = {
        "T0883": attack_pattern("T0883", "Internet Accessible Device"),
        "T0886": attack_pattern("T0886", "Remote Services"),
        "T0846": attack_pattern("T0846", "Remote System Discovery"),
        "T0843": attack_pattern("T0843", "Program Download"),
        "T0836": attack_pattern("T0836", "Modify Parameter"),
        "T0855": attack_pattern("T0855", "Unauthorized Command Message"),
    }
    coas = {
        "M0930": coa("M0930", "Network Segmentation",
                     "Keep press-line PLCs in a cell/area zone; no direct routes from enterprise or internet."),
        "M0937": coa("M0937", "Filter Network Traffic",
                     "Allow-list Modbus/EtherNet/IP sources at the cell firewall; block writes from non-HMI hosts."),
        "M0932": coa("M0932", "Multi-factor Authentication",
                     "Require MFA on vendor VPN and remote desktop into the OT DMZ."),
    }

    ind = [
        indicator("c2-ip", "PRESSBREAK C2 server", "[ipv4-addr:value = '203.0.113.45']",
                  "Primary C2 observed beaconing over TCP/443.", kill_chain_phases=[
                      {"kill_chain_name": "mitre-ics-attack", "phase_name": "command-and-control"}]),
        indicator("c2-backup", "PRESSBREAK backup C2 pair",
                  "[ipv4-addr:value = '203.0.113.46' OR ipv4-addr:value = '203.0.113.47']"),
        indicator("c2-domain", "PRESSBREAK C2 domain", "[domain-name:value = 'update-plcsync.example']"),
        indicator("payload-url", "PRESSBREAK payload URL",
                  "[url:value = 'http://update-plcsync.example/fw/patch.bin']"),
        indicator("payload-hash", "PRESSBREAK loader (SHA-256)",
                  f"[file:hashes.'SHA-256' = '{fake_sha256('pressbreak-loader')}']"),
        indicator("staging-net", "COPPER LATHE staging range", "[ipv4-addr:value = '198.51.100.0/24']",
                  "VPS range used to host GRIDSWEEP scans.", indicator_types=["anomalous-activity"]),
        indicator("vpn-brute", "Vendor VPN brute-force source", "[ipv4-addr:value = '192.0.2.77']",
                  indicator_types=["anomalous-activity"]),
        # revoked: should never show up in hunts / exports
        indicator("retired-ip", "Retired sinkholed C2", "[ipv4-addr:value = '192.0.2.200']",
                  modified=T1, revoked=True),
    ]
    i_c2, i_bk, i_dom, i_url, i_hash, i_net, i_vpn = ind[:7]

    rels = [
        rel(iset, "attributed-to", actor),
        rel(campaign, "attributed-to", iset),
        rel(iset, "uses", malware),
        rel(iset, "uses", scanner),
        rel(iset, "targets", sector),
        rel(campaign, "targets", vuln),
        rel(malware, "targets", sector),
        rel(iset, "uses", aps["T0883"]),
        rel(iset, "uses", aps["T0886"]),
        rel(scanner, "uses", aps["T0846"]),
        rel(malware, "uses", aps["T0843"]),
        rel(malware, "uses", aps["T0836"]),
        rel(malware, "uses", aps["T0855"]),
        rel(coas["M0930"], "mitigates", aps["T0883"]),
        rel(coas["M0932"], "mitigates", aps["T0886"]),
        rel(coas["M0937"], "mitigates", aps["T0855"]),
        rel(coas["M0937"], "mitigates", aps["T0836"]),
    ]
    for i in (i_c2, i_bk, i_dom, i_url, i_hash):
        rels.append(rel(i, "indicates", malware))
    rels.append(rel(i_net, "indicates", scanner))
    rels.append(rel(i_vpn, "indicates", campaign))

    objects = [PRODUCER, sector, actor, iset, campaign, malware, scanner, vuln,
               *aps.values(), *coas.values(), *ind, *rels]
    return bundle(objects, "ICS Threats - Manufacturing",
                  "Fictional ICS/OT threat activity against stamping and press-line environments.")


def it_bundle() -> dict:
    ransomware = base("malware", "lockstep", "LOCKSTEP", is_family=True, malware_types=["ransomware"],
                      description="Fictional commodity ransomware that encrypts MES/historian servers.")
    phish = attack_pattern("T1566", "Phishing", "enterprise-attack")
    encrypt = attack_pattern("T1486", "Data Encrypted for Impact", "enterprise-attack")
    ind = [
        indicator("lockstep-phish", "LOCKSTEP phishing domain", "[domain-name:value = 'invoice-portal.example']"),
        indicator("lockstep-hash", "LOCKSTEP encryptor (SHA-256)",
                  f"[file:hashes.'SHA-256' = '{fake_sha256('lockstep-encryptor')}']"),
        indicator("lockstep-c2", "LOCKSTEP exfil server", "[ipv4-addr:value = '198.51.100.200']"),
        indicator("lockstep-mail", "LOCKSTEP sender", "[email-addr:value = 'ap-billing@invoice-portal.example']"),
    ]
    rels = [rel(i, "indicates", ransomware) for i in ind]
    rels += [rel(ransomware, "uses", phish), rel(ransomware, "uses", encrypt)]
    return bundle([PRODUCER, ransomware, phish, encrypt, *ind, *rels], "IT Commodity Threats",
                  "Fictional ransomware activity that commonly crosses from IT into OT networks.")


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    for fname, b in (("ics_threats.json", ics_bundle()), ("it_commodity.json", it_bundle())):
        (OUT / fname).write_text(json.dumps(b, indent=2) + "\n")
        print(f"wrote {OUT / fname} ({len(b['objects'])} objects)")
