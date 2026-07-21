"""Finding embeddings for global deduplication.

Generates vector embeddings from finding text and stores them in the
finding.embedding column (pgvector vector(384) type).

Uses sentence-transformers all-MiniLM-L6-v2 (runs locally, no API key needed).
The embedding is computed from a concatenation of title, description, and
exploit_scenario.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

import psycopg

if TYPE_CHECKING:
    from llmpuffin.db import DB

log = logging.getLogger("llmpuffin")

EMBEDDING_MODEL = "all-MiniLM-L6-v2"
EMBEDDING_DIMS = 384

# Lazy-loaded singleton — the model is ~80MB and takes a moment to load,
# so we only do it once per process.
_model = None


def _get_model():
    global _model
    if _model is None:
        log.info("Loading sentence_transformers")
        from sentence_transformers import SentenceTransformer

        hf_logger = logging.getLogger("huggingface_hub")
        hf_logger.setLevel(logging.DEBUG)

        log.info("Loading embedding model %s...", EMBEDDING_MODEL)
        _model = SentenceTransformer(EMBEDDING_MODEL, backend="onnx")
        log.info("Embedding model loaded")
    return _model


def _finding_text(finding) -> str:
    """Build the text to embed from a finding's fields."""
    parts = []
    if finding.title:
        parts.append(finding.title)
    if finding.description:
        parts.append(finding.description)
    if finding.exploit_scenario:
        parts.append(finding.exploit_scenario)
    return "\n\n".join(parts)


def _embed_texts(texts: list[str]) -> list[list[float]]:
    """Encode texts using the local sentence-transformers model."""
    log.info("Preparing model")
    model = _get_model()
    embeddings = model.encode(texts, normalize_embeddings=True)
    return [e.tolist() for e in embeddings]


def embed_finding(finding_id: int, *, db: DB) -> bool:
    """Generate and store an embedding for a single finding. Returns True on success."""
    from llmpuffin.models import Finding

    with db.sync_session() as s:
        finding = s.get(Finding, finding_id)
        if finding is None:
            return False
        text = _finding_text(finding)
        if not text.strip():
            return False
        try:
            vecs = _embed_texts([text])
            finding.embedding = vecs[0]
            s.commit()
            return True
        except Exception as exc:
            log.warning("Failed to embed finding %d: %s", finding_id, exc)
            return False


async def backfill_embeddings(*, db: DB, batch_size: int = 50) -> int:
    """Generate embeddings for all findings that don't have one yet.

    Returns the number of findings embedded.
    """
    import asyncio

    from sqlalchemy import select
    from sqlalchemy import update as sa_update

    from llmpuffin.models import Finding

    # Fetch finding IDs + text to embed.
    async with db.async_session() as s:
        findings = (
            await s.execute(
                select(
                    Finding.id,
                    Finding.title,
                    Finding.description,
                    Finding.exploit_scenario,
                )
                .where(Finding.embedding.is_(None), Finding.status != "deleted")
                .order_by(Finding.id)
            )
        ).all()

    total = len(findings)
    if not total:
        return 0

    logging.info("Found %d findings to backfill", total)

    count = 0
    for i in range(0, total, batch_size):
        batch = findings[i : i + batch_size]
        texts = []
        ids = []
        for fid, title, description, exploit_scenario in batch:
            parts = [p for p in (title, description, exploit_scenario) if p]
            text = "\n\n".join(parts)
            if text.strip():
                texts.append(text)
                ids.append(fid)
        if not texts:
            continue
        try:
            vecs = await asyncio.to_thread(_embed_texts, texts)
            async with db.async_session() as s:
                for fid, vec in zip(ids, vecs):
                    await s.execute(
                        sa_update(Finding)
                        .where(Finding.id == fid)
                        .values(embedding=vec)
                    )
                await s.commit()
            count += len(ids)
            log.info("Embedded %d/%d findings", count, total)
        except Exception as exc:
            log.warning("Failed to embed batch: %s", exc)

    return count


def main() -> None:
    """CLI entrypoint: backfill embeddings for all findings missing them."""
    import asyncio

    from llmpuffin.config import Config
    from llmpuffin.db import DB
    from llmpuffin.log import setup as setup_logging

    config = Config.load()
    setup_logging(level=config.logging.level)
    db = DB(config.postgres)
    count = asyncio.run(backfill_embeddings(db=db))
    print(f"Embedded {count} finding(s)")


@dataclass
class FindingCluster:
    """A group of similar findings."""

    finding_ids: list[int]
    """Primary key IDs of findings in this cluster, ordered by oldest first."""


def cluster_findings(
    *, db: DB, threshold: float = 0.8, max_neighbors: int = 20
) -> list[FindingCluster]:
    """Cluster all non-deleted findings with embeddings.

    For each finding, queries the ``max_neighbors`` nearest neighbors
    using pgvector's indexed cosine distance. Pairs above ``threshold``
    become edges, then connected components are computed via union-find.

    Returns clusters with 2+ findings, sorted largest-first.
    """
    # Step 1: fetch all finding IDs + embeddings that are eligible.
    with psycopg.connect(db.url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, embedding::text
                FROM finding
                WHERE status != 'deleted'
                  AND embedding IS NOT NULL
                ORDER BY id
                """
            )
            rows = cur.fetchall()

    if len(rows) < 2:
        return []

    # Step 2: for each finding, query its nearest neighbors via pgvector.
    parent: dict[int, int] = {}

    def find(x: int) -> int:
        while parent.get(x, x) != x:
            parent[x] = parent.get(parent[x], parent[x])
            x = parent[x]
        return x

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    with psycopg.connect(db.url) as conn:
        with conn.cursor() as cur:
            for fid, embedding_text in rows:
                parent.setdefault(fid, fid)
                cur.execute(
                    """
                    SELECT id, 1 - (embedding <=> %s::vector) AS similarity
                    FROM finding
                    WHERE id != %s
                      AND status != 'deleted'
                      AND embedding IS NOT NULL
                    ORDER BY embedding <=> %s::vector
                    LIMIT %s
                    """,
                    (embedding_text, fid, embedding_text, max_neighbors),
                )
                for neighbor_id, similarity in cur.fetchall():
                    if float(similarity) >= threshold:
                        parent.setdefault(neighbor_id, neighbor_id)
                        union(fid, neighbor_id)

    # Step 3: group by root.
    groups: dict[int, list[int]] = {}
    for node in parent:
        root = find(node)
        groups.setdefault(root, []).append(node)

    # Only keep clusters with 2+ members, sort by size descending.
    clusters = [
        FindingCluster(finding_ids=sorted(ids))
        for ids in groups.values()
        if len(ids) >= 2
    ]
    clusters.sort(key=lambda c: len(c.finding_ids), reverse=True)
    return clusters


def find_similar_by_vector(
    vector: list[float],
    *,
    db: DB,
    exclude_id: int | None = None,
    audit_run_id: int | None = None,
    threshold: float = 0.8,
    limit: int = 10,
) -> list[tuple[int, float]]:
    """Find similar findings by comparing a vector against stored embeddings.

    Returns list of (finding_id, similarity_score) pairs above threshold,
    highest first. Optionally scope to a single audit run and/or exclude a
    specific finding id.
    """
    vec_literal = "[" + ",".join(str(float(v)) for v in vector) + "]"

    conditions = ["status != 'deleted'", "embedding IS NOT NULL"]
    params: list = [vec_literal]

    if exclude_id is not None:
        conditions.append("id != %s")
        params.append(exclude_id)
    if audit_run_id is not None:
        conditions.append("audit_run_id = %s")
        params.append(audit_run_id)

    where = " AND ".join(conditions)
    params.extend([vec_literal, limit])

    results = []
    with psycopg.connect(db.url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT id, 1 - (embedding <=> %s::vector) AS similarity
                FROM finding
                WHERE {where}
                ORDER BY embedding <=> %s::vector
                LIMIT %s
                """,
                params,
            )
            for row in cur.fetchall():
                sim = float(row[1])
                if sim >= threshold:
                    results.append((row[0], round(sim, 3)))

    return results


def find_similar_global(
    finding_id: int, *, db: DB, threshold: float = 0.8, limit: int = 10
) -> list[tuple[int, float]]:
    """Find globally similar findings using cosine similarity on embeddings.

    Returns list of (finding_id, similarity_score) pairs, highest first.
    Threshold is cosine similarity (0-1, higher = more similar).
    """
    from llmpuffin.models import Finding

    with db.sync_session() as s:
        finding = s.get(Finding, finding_id)
        if finding is None or finding.embedding is None:
            return []

    return find_similar_by_vector(
        finding.embedding,
        db=db,
        exclude_id=finding_id,
        threshold=threshold,
        limit=limit,
    )


async def find_similar_findings(
    finding_id: int, *, db: DB, threshold: float = 0.8, limit: int = 10
) -> list[tuple]:
    """Find similar findings with full Finding objects loaded.

    Returns list of (Finding, similarity_score) pairs, highest first.
    Each Finding has audit_run and profile eagerly loaded.
    """
    from sqlalchemy import select
    from sqlalchemy.orm import selectinload

    from llmpuffin.models import AuditRun, Finding

    similar_ids = find_similar_global(
        finding_id, db=db, threshold=threshold, limit=limit
    )
    if not similar_ids:
        return []

    sf_ids = [gid for gid, _ in similar_ids]
    sf_scores = {gid: score for gid, score in similar_ids}

    async with db.async_session() as s:
        rows = (
            (
                await s.execute(
                    select(Finding)
                    .where(Finding.id.in_(sf_ids))
                    .options(
                        selectinload(Finding.audit_run).selectinload(AuditRun.profile),
                    )
                )
            )
            .scalars()
            .all()
        )

    return sorted(
        [(f, sf_scores[f.id]) for f in rows],
        key=lambda x: x[1],
        reverse=True,
    )
