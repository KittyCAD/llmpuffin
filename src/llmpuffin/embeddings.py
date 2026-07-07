"""Finding embeddings for global deduplication.

Generates vector embeddings from finding text and stores them in the
finding.embedding column (pgvector vector(384) type).

Uses sentence-transformers all-MiniLM-L6-v2 (runs locally, no API key needed).
The embedding is computed from a concatenation of title, description, and
exploit_scenario.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

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
        from sentence_transformers import SentenceTransformer

        _model = SentenceTransformer(EMBEDDING_MODEL)
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


def backfill_embeddings(*, db: DB, batch_size: int = 50) -> int:
    """Generate embeddings for all findings that don't have one yet.

    Returns the number of findings embedded.
    """
    from sqlalchemy import select

    from llmpuffin.models import Finding

    count = 0
    with db.sync_session() as s:
        findings = (
            s.execute(
                select(Finding)
                .where(Finding.embedding.is_(None), Finding.status != "deleted")
                .order_by(Finding.id)
            )
            .scalars()
            .all()
        )

        for i in range(0, len(findings), batch_size):
            batch = findings[i : i + batch_size]
            texts = [_finding_text(f) for f in batch]
            valid = [(f, t) for f, t in zip(batch, texts) if t.strip()]
            if not valid:
                continue
            try:
                vecs = _embed_texts([t for _, t in valid])
                for (f, _), vec in zip(valid, vecs):
                    f.embedding = vec
                    count += 1
                s.commit()
                log.info("Embedded batch of %d findings", len(valid))
            except Exception as exc:
                log.warning("Failed to embed batch: %s", exc)
                s.rollback()

    log.info("Backfill complete: %d findings embedded", count)
    return count


def main() -> None:
    """CLI entrypoint: backfill embeddings for all findings missing them."""
    from llmpuffin.config import Config
    from llmpuffin.db import DB
    from llmpuffin.log import setup as setup_logging

    config = Config.load()
    setup_logging(level=config.logging.level)
    db = DB(config.postgres)
    count = backfill_embeddings(db=db)
    print(f"Embedded {count} finding(s)")


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

    import psycopg

    vec_literal = "[" + ",".join(str(float(v)) for v in finding.embedding) + "]"

    results = []
    with psycopg.connect(db.url) as conn:
        with conn.cursor() as cur:
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
                (vec_literal, finding_id, vec_literal, limit),
            )
            for row in cur.fetchall():
                sim = float(row[1])
                if sim >= threshold:
                    results.append((row[0], round(sim, 3)))

    return results
