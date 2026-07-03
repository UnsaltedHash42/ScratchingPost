"""Wazuh custom detection content (profiles/wazuh/).

Structural checks on the shipped ruleset/decoders/log-source so a typo can't ship a
manager config that silently fails to load. No live Wazuh needed — this validates the
XML is well-formed, rule ids stay in the reserved user range, rules chain off the base
rule, MITRE ids are attached, and the rules key on fields the recorder actually emits.
"""

import xml.etree.ElementTree as ET
from pathlib import Path

from orchestrator.contracts.events import EventType

WAZUH = Path(__file__).parent.parent / "profiles" / "wazuh"


def _rules_root():
    # local_rules.xml has a single <group> root; parse directly.
    return ET.parse(WAZUH / "local_rules.xml").getroot()


def test_files_present():
    for f in ("local_rules.xml", "local_decoder.xml", "ossec.conf.snippet", "README.md"):
        assert (WAZUH / f).exists(), f


def test_rules_xml_well_formed_and_in_user_range():
    rules = _rules_root().findall("rule")
    assert rules
    for rule in rules:
        # Wazuh reserves 100000+ for user rules; colliding with built-ins breaks loads.
        assert int(rule.get("id")) >= 100000
        assert 0 <= int(rule.get("level")) <= 15


def test_base_rule_and_children_chain():
    rules = {r.get("id"): r for r in _rules_root().findall("rule")}
    assert "100000" in rules
    base = rules["100000"]
    assert base.findtext("decoded_as") == "json"
    assert base.get("level") == "0"  # base alone doesn't alert
    # Every other rule chains off the base via <if_sid>.
    for rid, rule in rules.items():
        if rid == "100000":
            continue
        assert rule.findtext("if_sid") == "100000", rid


def test_attack_rules_carry_mitre_ids():
    rules = _rules_root().findall("rule")
    mitre_rules = [r for r in rules if r.find("mitre") is not None]
    assert mitre_rules
    for rule in mitre_rules:
        ids = [e.text for e in rule.find("mitre").findall("id")]
        assert ids and all(i and i.startswith("T") for i in ids)


def test_rules_reference_real_event_types():
    # The event_type values the rules match must exist in the uniform taxonomy, or a
    # rule can never fire against real telemetry.
    valid = {e.value for e in EventType}
    text = (WAZUH / "local_rules.xml").read_text()
    for rule in _rules_root().findall("rule"):
        for field in rule.findall("field"):
            if field.get("name") != "event_type":
                continue
            for token in field.text.replace("^", "").replace("$", "").split("|"):
                assert token in valid, token
    assert "event_type" in text


def test_decoder_and_localfile_well_formed():
    # local_decoder.xml has sibling <decoder> elements (no single root); wrap to parse.
    dec = ET.fromstring("<root>" + (WAZUH / "local_decoder.xml").read_text().split("-->", 1)[1] + "</root>")
    names = {d.get("name") for d in dec.findall("decoder")}
    assert {"scratchingpost-esf", "scratchingpost-esf-json"} <= names

    snippet = ET.fromstring("<root>" + (WAZUH / "ossec.conf.snippet").read_text().split("-->", 1)[1] + "</root>")
    localfile = snippet.find("localfile")
    assert localfile.findtext("log_format") == "json"
