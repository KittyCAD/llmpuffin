"""Persist InMemoryStore to/from disk as JSON."""

from __future__ import annotations

import json
from pathlib import Path

from langgraph.store.memory import InMemoryStore


STORE_FILE = "store.json"


def load_store(store_dir: Path) -> InMemoryStore:
    """Load an InMemoryStore from a JSON file on disk, or create a fresh one."""
    store = InMemoryStore()
    path = store_dir / STORE_FILE
    if path.exists():
        data = json.loads(path.read_text())
        for item in data:
            store.put(
                namespace=tuple(item["namespace"]),
                key=item["key"],
                value=item["value"],
            )
    return store


def save_store(store: InMemoryStore, store_dir: Path) -> None:
    """Persist an InMemoryStore to a JSON file on disk."""
    store_dir.mkdir(parents=True, exist_ok=True)
    items = []
    # Search with empty namespace tuple and empty filter to get everything
    for ns_path, ns_items in store._data.items():
        for key, item in ns_items.items():
            items.append({
                "namespace": list(ns_path),
                "key": key,
                "value": item.value,
            })
    path = store_dir / STORE_FILE
    path.write_text(json.dumps(items, indent=2))
