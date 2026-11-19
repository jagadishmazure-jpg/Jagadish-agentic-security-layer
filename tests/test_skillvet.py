"""Skill-vetting checks (SKILL-01..06): static supply-chain audit.

The vetter never executes skill code; the no-execution test proves it
with a package whose code would create a file if it ever ran.
"""

import pytest

from agelayer import skillvet

CLEAN_SKILL = {
    "SKILL.md": "# Word Count Helper\n\n"
                "Counts the words in a piece of text the user provides "
                "and reports the total, the average word length, and "
                "the longest word it finds in the passage.\n",
    "helper.py": "def count_words(text):\n"
                 "    words = text.split()\n"
                 "    return len(words)\n",
}


def _severities(report):
    return {f.policy_id for f in report.findings}


def test_pattern_set_is_non_empty():
    # An empty pattern list must fail loudly, not silently pass every
    # package as clean: each group carries patterns and the total is
    # asserted before any audit runs.
    assert skillvet.pattern_count() > 0
    for group in (skillvet.SHELL_PATTERNS, skillvet.NETWORK_PATTERNS,
                  skillvet.SENSITIVE_PATTERNS,
                  skillvet.OBFUSCATION_PATTERNS):
        assert len(group) > 0


def test_empty_pattern_set_fails_loudly(monkeypatch):
    monkeypatch.setattr(skillvet, "SHELL_PATTERNS", {})
    monkeypatch.setattr(skillvet, "NETWORK_PATTERNS", {})
    monkeypatch.setattr(skillvet, "ENDPOINT_PATTERNS", {})
    monkeypatch.setattr(skillvet, "SENSITIVE_PATTERNS", {})
    monkeypatch.setattr(skillvet, "OBFUSCATION_PATTERNS", {})
    with pytest.raises(RuntimeError):
        skillvet.vet_skill(CLEAN_SKILL, {"capabilities": []})


def test_clean_skill_allowed():
    report = skillvet.vet_skill(CLEAN_SKILL, {"capabilities": []})
    assert report.verdict == "ALLOW"
    assert report.findings == []
    assert report.detected_capabilities == []


def test_hidden_network_call_blocked():
    files = {"helper.py": "import requests\n"
                          "def fetch(url):\n"
                          "    return requests.get(url).text\n"}
    report = skillvet.vet_skill(files, {"capabilities": []})
    assert report.verdict == "BLOCK"
    assert "SKILL-02" in _severities(report)
    assert "network" in report.detected_capabilities


def test_undeclared_shell_out_blocked():
    files = {"helper.py": "import subprocess\n"
                          "def run(cmd):\n"
                          "    return subprocess.run(cmd)\n"}
    report = skillvet.vet_skill(files, {"capabilities": []})
    assert report.verdict == "BLOCK"
    assert "SKILL-01" in _severities(report)


def test_declared_shell_out_still_blocked():
    # Consistency: shell access from a loaded skill is BLOCK even when
    # declared — declaration does not sanitize it.
    files = {"helper.py": "import os\n"
                          "def run(cmd):\n"
                          "    return os.system(cmd)\n"}
    report = skillvet.vet_skill(files, {"capabilities": ["shell"]})
    assert report.verdict == "BLOCK"
    assert "SKILL-01" in _severities(report)


def test_sensitive_path_read_flagged():
    files = {"helper.py": "def read_key():\n"
                          "    path = '~/.ssh/id_rsa'\n"
                          "    return open(path).read()\n"}
    report = skillvet.vet_skill(files, {"capabilities": []})
    assert "SKILL-03" in _severities(report)
    assert report.verdict in ("REVIEW", "BLOCK")


def test_environment_secret_access_flagged():
    files = {"helper.py": "import os\n"
                          "KEY = os.environ.get('SERVICE_KEY')\n"}
    report = skillvet.vet_skill(files, {"capabilities": []})
    assert "SKILL-03" in _severities(report)
    assert report.verdict != "ALLOW"


def test_base64_blob_flagged():
    blob = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVjZGVmZ2hpamtsbW5vcA=="
    files = {"data.py": f"PAYLOAD = '{blob}'\n"}
    report = skillvet.vet_skill(files, {"capabilities": []})
    assert "SKILL-04" in _severities(report)
    assert report.verdict == "REVIEW"


def test_declared_matches_actual_passes():
    files = {"helper.py": "import requests\n"
                          "def fetch(url):\n"
                          "    return requests.get(url).text\n"}
    report = skillvet.vet_skill(files, {"capabilities": ["network"]})
    assert report.verdict == "ALLOW"
    assert "SKILL-02" not in _severities(report)
    assert report.detected_capabilities == ["network"]


def test_empty_package_handled():
    report = skillvet.vet_skill({}, {"capabilities": []})
    assert report.verdict == "REVIEW"
    assert "SKILL-06" in _severities(report)


def test_vetter_never_executes_skill_code(tmp_path):
    sentinel = tmp_path / "pwned.txt"
    files = {"evil.py": f"open(r'{sentinel}', 'w').write('pwned')\n"}
    skillvet.vet_skill(files, {"capabilities": []})
    assert not sentinel.exists()


def test_load_skill_dir_roundtrip(tmp_path):
    pkg = tmp_path / "myskill"
    pkg.mkdir()
    (pkg / "SKILL.md").write_text(CLEAN_SKILL["SKILL.md"])
    (pkg / "helper.py").write_text(CLEAN_SKILL["helper.py"])
    files = skillvet.load_skill_dir(str(pkg))
    assert set(files) == {"SKILL.md", "helper.py"}
    report = skillvet.vet_skill(files, {"capabilities": []})
    assert report.verdict == "ALLOW"
