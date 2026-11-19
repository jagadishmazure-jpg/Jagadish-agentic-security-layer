"""Skill vetting: static supply-chain audit of agent-skill packages.

Agent skills are reusable instruction/code packages an agent loads and
trusts. This vetter audits a package WITHOUT executing any of its code:
it pattern-matches the file contents for dangerous capabilities and
compares what the code actually does against what the package manifest
declares. Undeclared capability is the supply-chain failure mode — the
skill that was reviewed is not the skill that runs.

Policy IDs:
  SKILL-01 - shell execution capability in skill code (BLOCK; shell
             access from a loaded skill is never acceptable, declared
             or not)
  SKILL-02 - capability detected in code but not declared in the
             manifest (BLOCK)
  SKILL-03 - read of sensitive paths or environment secrets (HIGH)
  SKILL-04 - obfuscation: base64 blobs or decode calls (MEDIUM)
  SKILL-05 - network endpoint literal in code (LOW, noted)
  SKILL-06 - empty package: nothing to audit (MEDIUM)

Verdict: BLOCK if any BLOCK finding, else REVIEW if any HIGH or MEDIUM
finding, else ALLOW. The detection pattern set is asserted non-empty at
audit time: an empty pattern list must fail loudly, never silently pass
every package as clean.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

SHELL_PATTERNS = {
    "subprocess module": r"\bsubprocess\b",
    "os.system call": r"\bos\.system\s*\(",
    "os.popen call": r"\bos\.popen\s*\(",
    "eval call": r"\beval\s*\(",
    "exec call": r"\bexec\s*\(",
    "shell=True flag": r"shell\s*=\s*True",
}

NETWORK_PATTERNS = {
    "requests library": r"\brequests\s*\.",
    "urllib": r"\burllib\b",
    "socket module": r"\bsocket\s*\.",
    "http.client": r"\bhttp\.client\b",
    "httpx library": r"\bhttpx\s*\.",
}

ENDPOINT_PATTERNS = {
    "url literal": r"https?://[^\s\"')]+",
}

SENSITIVE_PATTERNS = {
    "ssh directory": r"\.ssh\b",
    "env file": r"\.env\b",
    "credential file": r"credential",
    "private key file": r"id_rsa|\.pem\b|private[_-]?key",
    "environment access": r"os\.environ|getenv\s*\(",
    "home expansion": r"expanduser\s*\(\s*[\"']~",
}

OBFUSCATION_PATTERNS = {
    "base64 decode": r"b64decode\s*\(",
    "codecs decode": r"codecs\.decode\s*\(",
    "base64 blob": r"[A-Za-z0-9+/]{48,}={0,2}",
}


def _pattern_groups() -> dict:
    return {
        "shell": SHELL_PATTERNS,
        "network": NETWORK_PATTERNS,
        "endpoint": ENDPOINT_PATTERNS,
        "sensitive": SENSITIVE_PATTERNS,
        "obfuscation": OBFUSCATION_PATTERNS,
    }


def pattern_count() -> int:
    """Total detection patterns across all groups (must be > 0)."""
    return sum(len(g) for g in _pattern_groups().values())


@dataclass
class Finding:
    severity: str   # BLOCK | HIGH | MEDIUM | LOW
    policy_id: str
    path: str
    detail: str     # pattern name + line number; never file content


@dataclass
class VetReport:
    verdict: str    # ALLOW | REVIEW | BLOCK
    findings: list = field(default_factory=list)
    detected_capabilities: list = field(default_factory=list)
    declared_capabilities: list = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "findings": [vars(f) for f in self.findings],
            "detected_capabilities": list(self.detected_capabilities),
            "declared_capabilities": list(self.declared_capabilities),
        }


_SEVERITY_ORDER = {"BLOCK": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _verdict(findings: list) -> str:
    severities = {f.severity for f in findings}
    if "BLOCK" in severities:
        return "BLOCK"
    if severities & {"HIGH", "MEDIUM"}:
        return "REVIEW"
    return "ALLOW"


def _line_of(content: str, match) -> int:
    return content.count("\n", 0, match.start()) + 1


def vet_skill(files: dict, manifest: dict = None) -> VetReport:
    """Audit a skill package given as {path: content}. Never executes it.

    manifest is a dict like {"capabilities": ["network"]}: the
    capabilities the package declares. Capabilities detected in code
    but absent from the manifest are BLOCK findings (SKILL-02).
    """
    groups = _pattern_groups()
    if sum(len(g) for g in groups.values()) == 0:
        raise RuntimeError(
            "skill vetting pattern set is empty; refusing to audit "
            "(an empty pattern set would silently pass every package)")
    declared = set((manifest or {}).get("capabilities", []))
    findings: list = []
    detected: set = set()
    capability_paths: dict = {}

    if not files:
        findings.append(Finding(
            "MEDIUM", "SKILL-06", "",
            "empty package: nothing to audit"))
        return VetReport(verdict=_verdict(findings), findings=findings,
                         detected_capabilities=[],
                         declared_capabilities=sorted(declared))

    def note_capability(cap: str, path: str) -> None:
        detected.add(cap)
        capability_paths.setdefault(cap, set()).add(path)

    for path in sorted(files):
        content = files[path]
        if isinstance(content, bytes):
            content = content.decode("utf-8", "replace")
        else:
            content = str(content)
        for name, pattern in groups["shell"].items():
            m = re.search(pattern, content)
            if m:
                note_capability("shell", path)
                findings.append(Finding(
                    "BLOCK", "SKILL-01", path,
                    f"shell execution pattern '{name}' "
                    f"(line {_line_of(content, m)})"))
        for _name, pattern in groups["network"].items():
            if re.search(pattern, content):
                note_capability("network", path)
        for name, pattern in groups["endpoint"].items():
            m = re.search(pattern, content)
            if m:
                note_capability("network", path)
                findings.append(Finding(
                    "LOW", "SKILL-05", path,
                    f"network endpoint '{name}' "
                    f"(line {_line_of(content, m)})"))
        for name, pattern in groups["sensitive"].items():
            m = re.search(pattern, content)
            if m:
                findings.append(Finding(
                    "HIGH", "SKILL-03", path,
                    f"sensitive access pattern '{name}' "
                    f"(line {_line_of(content, m)})"))
        for name, pattern in groups["obfuscation"].items():
            m = re.search(pattern, content)
            if m:
                findings.append(Finding(
                    "MEDIUM", "SKILL-04", path,
                    f"obfuscation pattern '{name}' "
                    f"(line {_line_of(content, m)})"))

    for cap in sorted(detected - declared):
        if cap == "shell":
            continue  # already BLOCK via SKILL-01, declared or not
        findings.append(Finding(
            "BLOCK", "SKILL-02", sorted(capability_paths[cap])[0],
            f"capability '{cap}' detected in code but not declared "
            "in the manifest"))

    findings.sort(key=lambda f: (_SEVERITY_ORDER[f.severity],
                                 f.path, f.policy_id))
    return VetReport(verdict=_verdict(findings), findings=findings,
                     detected_capabilities=sorted(detected),
                     declared_capabilities=sorted(declared))


def load_skill_dir(root) -> dict:
    """Load a skill package directory into a {path: content} file map."""
    files = {}
    for dirpath, _dirs, names in os.walk(root):
        for name in sorted(names):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            with open(full, "rb") as fh:
                files[rel] = fh.read().decode("utf-8", "replace")
    return files
