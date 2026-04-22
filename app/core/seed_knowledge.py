"""
app/memory/seed_knowledge.py

Pre-seeds ChromaDB with curated OWASP Top 10 + CWE cybersecurity knowledge.
This gives the AI a strong RAG foundation so it doesn't hallucinate vulnerability
descriptions or fixes — it draws from authoritative references.

Run once:
    docker compose exec backend python -m app.memory.seed_knowledge
"""
import os
import uuid
import chromadb
from app.knowledge.security import KNOWLEDGE_ENTRIES

COLLECTION_NAME = "security_knowledge_base"

# ---------------------------------------------------------------------------
# Authoritative vulnerability knowledge entries
# ---------------------------------------------------------------------------

def seed(force: bool = False):
    """Seed the ChromaDB knowledge base. Skips if already seeded (unless force=True)."""
    host = os.getenv("CHROMA_HOST", "localhost")
    port = 8000 if host == "chromadb_server" else 8001

    print(f"🔗 Connecting to ChromaDB at {host}:{port}…")
    client = chromadb.HttpClient(host=host, port=port)
    collection = client.get_or_create_collection(
        name=COLLECTION_NAME,
        metadata={"description": "SentryAgent cybersecurity knowledge base"},
    )

    existing = collection.count()
    if existing > 0 and not force:
        print(f"✅ Knowledge base already has {existing} entries. Use --force to re-seed.")
        return

    if force and existing > 0:
        print(f"🗑️  Clearing {existing} existing entries…")
        client.delete_collection(COLLECTION_NAME)
        collection = client.get_or_create_collection(name=COLLECTION_NAME)

    print(f"📚 Seeding {len(KNOWLEDGE_ENTRIES)} cybersecurity knowledge entries…")

    ids, documents, metadatas = [], [], []

    for entry in KNOWLEDGE_ENTRIES:
        doc_id = str(uuid.uuid4())
        document_text = (
            f"[VULNERABILITY TYPE]: {entry['type']}\n"
            f"[CWE]: {entry['cwe']} | [OWASP]: {entry['owasp']} | [SEVERITY]: {entry['severity']}\n"
            f"[DESCRIPTION]: {entry['description']}\n"
            f"[HOW TO DETECT]: {entry['detection']}\n"
            f"[FIX PATTERN]:\n{entry['fix']}"
        )
        ids.append(doc_id)
        documents.append(document_text)
        metadatas.append({
            "type": entry["type"],
            "cwe": entry["cwe"],
            "owasp": entry["owasp"],
            "severity": entry["severity"],
        })

    collection.add(ids=ids, documents=documents, metadatas=metadatas)
    print(f"✅ Seeded {len(KNOWLEDGE_ENTRIES)} entries into '{COLLECTION_NAME}'.")


if __name__ == "__main__":
    import sys
    force = "--force" in sys.argv
    seed(force=force)
