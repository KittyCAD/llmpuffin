"""File coverage tracking for audit runs.

Records which files in /src the agent accessed during an audit, and via
which tool. Each access is persisted to the database immediately.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from llmpuffin.audit_environment import AuditExecution
    from llmpuffin.db import DB

log = logging.getLogger("llmpuffin")

# Paths we never want to track
_IGNORE_PREFIXES = ("/proc/", "/sys/", "/dev/", "/tmp/", "/etc/", "/run/")


def _normalize(path: str, code_dir: str) -> str | None:
    """Normalize a path relative to the code_dir, return None if outside."""
    path = path.strip()
    if not path:
        return None
    # Already relative
    if not path.startswith("/"):
        path = f"{code_dir.rstrip('/')}/{path}"
    # Must be under code_dir
    prefix = code_dir.rstrip("/") + "/"
    if not path.startswith(prefix) and path != code_dir.rstrip("/"):
        return None
    for p in _IGNORE_PREFIXES:
        if path.startswith(p):
            return None
    # Return relative to code_dir
    return path[len(prefix) :]


def _extract_paths_from_exec(command: str, _stdout: str) -> set[str]:
    """Try to extract file paths from common shell commands."""
    paths: set[str] = set()

    # cat/head/tail/less/more <file>
    for cmd_prefix in ("cat ", "head ", "tail ", "less ", "more ", "bat "):
        if cmd_prefix in command:
            # Extract args after the command, skip flags
            parts = command.split(cmd_prefix, 1)[1].split()
            for part in parts:
                if not part.startswith("-") and ("." in part or "/" in part):
                    paths.add(part)

    return paths


@dataclass
class CoverageTracker:
    """Persists file access events directly to the database.

    Each record_* call writes to the DB immediately via upsert.
    A local set avoids redundant DB writes for already-seen entries.
    """

    audit_run_id: int
    code_dir: str
    db: DB
    _seen: set[tuple[str, str]] = field(default_factory=set)

    def _persist(self, rel_path: str, access_type: str) -> None:
        """Insert a coverage row, skipping duplicates."""
        key = (rel_path, access_type)
        if key in self._seen:
            return
        self._seen.add(key)

        try:
            from sqlalchemy.dialects.postgresql import insert
            from llmpuffin.models import FileCoverage

            with self.db.sync_session() as s:
                stmt = (
                    insert(FileCoverage)
                    .values(
                        audit_run_id=self.audit_run_id,
                        file_path=rel_path,
                        access_type=access_type,
                        tool_name=access_type,
                    )
                    .on_conflict_do_nothing(constraint="uq_file_coverage_run_path_type")
                )
                s.execute(stmt)
                s.commit()
        except Exception as exc:
            log.warning("Failed to persist coverage for %s: %s", rel_path, exc)

    def record(self, file_path: str, access_type: str) -> None:
        """Record that a file was accessed."""
        rel = _normalize(file_path, self.code_dir)
        if rel is None:
            return
        if access_type != "tree":
            log.info("coverage: %s %s", access_type, rel)
        self._persist(rel, access_type)

    def record_read(self, file_path: str) -> None:
        self.record(file_path, "read")

    def record_edit(self, file_path: str) -> None:
        self.record(file_path, "edit")

    def record_exec(self, command: str, stdout: str) -> None:
        """Extract file paths from exec command + output."""
        paths = _extract_paths_from_exec(command, stdout)
        for p in paths:
            self.record(p, "exec")


async def populate_file_tree(
    execution: AuditExecution, code_dir: str, *, audit_run_id: int, db: DB
) -> int:
    """Run find on code_dir and insert 'tree' entries into the DB.

    Returns the number of files found.
    """
    from sqlalchemy.dialects.postgresql import insert
    from llmpuffin.models import FileCoverage

    try:
        result = await execution.exec(
            ["find", code_dir, "-type", "f", "-not", "-path", "*/.git/*"],
            timeout=60,
        )
        if not result.ok:
            log.warning("find failed: %s", result.stderr.strip())
            return 0
        prefix = code_dir.rstrip("/") + "/"
        paths = sorted(
            line[len(prefix) :]
            for line in result.stdout.strip().split("\n")
            if line.strip() and line.startswith(prefix)
        )
        if not paths:
            return 0

        with db.sync_session() as s:
            for path in paths:
                stmt = (
                    insert(FileCoverage)
                    .values(
                        audit_run_id=audit_run_id,
                        file_path=path,
                        access_type="tree",
                        tool_name="tree",
                    )
                    .on_conflict_do_nothing(constraint="uq_file_coverage_run_path_type")
                )
                s.execute(stmt)
            s.commit()

        log.info("Populated file tree: %d files", len(paths))
        return len(paths)
    except Exception as exc:
        log.warning("Failed to populate file tree: %s", exc)
        return 0


# ── Coverage visualization ──


@dataclass
class DirNode:
    """A node in the file tree for coverage visualization."""

    name: str
    is_dir: bool = True
    children: dict[str, DirNode] = field(default_factory=dict)
    total_files: int = 0
    accessed_files: int = 0

    @property
    def coverage_pct(self) -> float:
        if self.total_files == 0:
            return 0.0
        return 100.0 * self.accessed_files / self.total_files

    @property
    def coverage_class(self) -> str:
        pct = self.coverage_pct
        if pct >= 80:
            return "coverage-high"
        if pct >= 40:
            return "coverage-medium"
        if pct > 0:
            return "coverage-low"
        return "coverage-none"


def build_coverage_tree(all_files: list[str], accessed: set[str]) -> DirNode:
    """Build a tree from file paths, annotating coverage.

    all_files: relative paths of all files in /src
    accessed: relative paths that were accessed
    """
    root = DirNode(name="/")

    # Insert all files into tree
    for path in all_files:
        parts = path.split("/")
        node = root
        for part in parts[:-1]:
            if part not in node.children:
                node.children[part] = DirNode(name=part)
            node = node.children[part]
        filename = parts[-1]
        leaf = DirNode(name=filename, is_dir=False)
        node.children[filename] = leaf

    # Mark accessed files
    for path in all_files:
        parts = path.split("/")
        node = root
        for part in parts[:-1]:
            node = node.children[part]
        leaf = node.children[parts[-1]]
        if path in accessed:
            leaf.total_files = 1
            leaf.accessed_files = 1
        else:
            leaf.total_files = 1
            leaf.accessed_files = 0

    # Roll up counts
    def _rollup(node: DirNode) -> tuple[int, int]:
        if not node.is_dir:
            return node.total_files, node.accessed_files
        total = 0
        acc = 0
        for child in node.children.values():
            t, a = _rollup(child)
            total += t
            acc += a
        node.total_files = total
        node.accessed_files = acc
        return total, acc

    _rollup(root)
    return root


def load_coverage_for_run(audit_run_id: int, *, db: DB) -> tuple[list[str], set[str]]:
    """Load coverage data from DB. Returns (all_files, accessed_set).

    all_files comes from 'tree' access_type entries.
    accessed comes from all other access_type entries.
    """
    from llmpuffin.models import FileCoverage
    from sqlalchemy import select

    with db.sync_session() as s:
        rows = s.execute(
            select(FileCoverage.file_path, FileCoverage.access_type)
            .where(FileCoverage.audit_run_id == audit_run_id)
            .order_by(FileCoverage.file_path)
        ).all()

    all_files: list[str] = []
    accessed: set[str] = set()
    for path, access_type in rows:
        if access_type == "tree":
            all_files.append(path)
        else:
            accessed.add(path)

    return sorted(set(all_files)), accessed
