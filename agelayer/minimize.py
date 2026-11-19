"""Context minimization: least-data at the context-construction step.

Permission to read a record is not permission to put the whole record
into the model's context. A ContextMinimizer is driven by per-task field
profiles: only the fields a task profile lists may pass into the
context; everything else is dropped (deny-by-default), including nested
fields addressed by dot paths ("contract.end_date"). A question about a
renewal date needs the customer name and the renewal date — not the
billing details, internal notes, and contacts that share the record.

Policy IDs:
  MIN-01 - unknown task profile in strict mode (fail-closed)
  MIN-02 - record is not a mapping (rejected, never partially minimized)

The minimization report lists the NAMES of kept and dropped fields
only. It never contains field values: values in a report would leak
exactly what minimization exists to protect.
"""

from __future__ import annotations

from dataclasses import dataclass, field


class MinimizeDenied(Exception):
    def __init__(self, policy_id, message):
        super().__init__(message)
        self.policy_id = policy_id


@dataclass
class MinimizationReport:
    task: str
    kept: list = field(default_factory=list)     # field paths, names only
    dropped: list = field(default_factory=list)  # field paths, names only

    def as_dict(self) -> dict:
        return {"task": self.task, "kept": list(self.kept),
                "dropped": list(self.dropped)}


# Example profiles: a renewal question needs three fields of the CRM
# record, not the record.
EXAMPLE_PROFILES = {
    "renewal_lookup": {"customer_name", "contract_end", "renewal_date"},
}


def _leaf_paths(record: dict, prefix: str = "") -> list:
    """All leaf field paths of a nested mapping (lists count as leaves)."""
    paths = []
    for key, value in record.items():
        path = f"{prefix}{key}"
        if isinstance(value, dict):
            paths.extend(_leaf_paths(value, prefix=path + "."))
        else:
            paths.append(path)
    return paths


def _is_kept(path: str, allowed: set) -> bool:
    """A leaf is kept if it is an allowed path or sits under one."""
    return any(path == a or path.startswith(a + ".") for a in allowed)


def _copy_path(src: dict, dst: dict, parts: list) -> None:
    value = src
    for part in parts:
        if not isinstance(value, dict) or part not in value:
            return
        value = value[part]
    node = dst
    for part in parts[:-1]:
        node = node.setdefault(part, {})
    node[parts[-1]] = value


class ContextMinimizer:
    """Deny-by-default field filter between a record and the context.

    profiles maps a task name to the set of field paths (dot paths for
    nested fields) that task may see. In strict mode an unknown task is
    denied (MIN-01); in non-strict mode it receives an empty context
    with every field reported as dropped.
    """

    def __init__(self, profiles: dict, strict: bool = True):
        self.profiles = {task: set(fields)
                          for task, fields in profiles.items()}
        self.strict = strict

    def minimize(self, task: str, record) -> tuple:
        """Return (minimized_record, MinimizationReport) for a task."""
        if not isinstance(record, dict):
            raise MinimizeDenied("MIN-02", "record must be a mapping")
        if task not in self.profiles:
            if self.strict:
                raise MinimizeDenied(
                    "MIN-01", f"no field profile for task: {task}")
            allowed: set = set()
        else:
            allowed = self.profiles[task]
        leaves = _leaf_paths(record)
        kept = sorted(p for p in leaves if _is_kept(p, allowed))
        dropped = sorted(p for p in leaves if not _is_kept(p, allowed))
        out: dict = {}
        for path in kept:
            _copy_path(record, out, path.split("."))
        return out, MinimizationReport(task=task, kept=kept,
                                       dropped=dropped)
