"""
app/memory/knowledge_base.py

SecurityKnowledgeBase — long-term organisational memory backed by ChromaDB.
Two responsibilities:
 1. recall_relevant_lessons() — RAG retrieval for audit & patch prompts
 2. learn_fix()               — store successful vulnerability→fix pairs
"""
import os
import uuid
import logging
import datetime
import chromadb

logger = logging.getLogger(__name__)

COLLECTION_NAME = "security_knowledge_base"


class SecurityKnowledgeBase:
    def __init__(self):
        from app.config.settings import CHROMA_HOST
        host = CHROMA_HOST
        port = 8000 if host == "chromadb_server" else 8001
        try:
            self.client = chromadb.HttpClient(host=host, port=port)
            self.collection = self.client.get_or_create_collection(
                name=COLLECTION_NAME,
                metadata={"description": "SentryAgent cybersecurity knowledge base"},
            )
            logger.info("ChromaDB connected (%s:%s) — %d entries", host, port, self.collection.count())
        except Exception as e:
            logger.warning("ChromaDB unavailable (%s). Knowledge base disabled.", e)
            self.collection = None

    # ------------------------------------------------------------------
    # RECALL — used by auditor and patcher to enrich AI prompts
    # ------------------------------------------------------------------

    def recall_relevant_lessons(self, query_text: str, n_results: int = 3) -> list[str]:
        """
        Semantic search against the knowledge base.
        Returns a list of formatted text snippets to inject into prompts.
        """
        if self.collection is None:
            return []
        try:
            count = self.collection.count()
            if count == 0:
                return []

            results = self.collection.query(
                query_texts=[query_text],
                n_results=min(n_results, count),
                include=["documents", "metadatas", "distances"],
            )

            lessons = []
            if results.get("documents"):
                for doc, meta, dist in zip(
                    results["documents"][0],
                    results["metadatas"][0],
                    results["distances"][0],
                ):
                    # Only include results that are reasonably relevant (lower distance = more similar)
                    if dist < 1.5:
                        severity = meta.get("severity", "")
                        vuln_type = meta.get("type", "")
                        lessons.append(f"[{severity}] {vuln_type}:\n{doc}")
            return lessons

        except Exception as e:
            logger.warning("Knowledge base lookup failed: %s", e)
            return []

    def recall_for_file(self, file_path: str, code_snippet: str = "", n_results: int = 4) -> list[str]:
        """
        Richer recall that combines file context + code hints for better relevance.
        """
        # Build a rich query that helps the embedding understand what we're looking at
        query = f"Security audit for Python file: {file_path}\n"
        if code_snippet:
            query += f"Code context:\n{code_snippet[:500]}"
        return self.recall_relevant_lessons(query, n_results=n_results)

    # ------------------------------------------------------------------
    # LEARN — used by the patch workflow after a successful fix
    # ------------------------------------------------------------------

    def learn_fix(
        self,
        vuln_type: str,
        description: str,
        fix_code: str,
        file_path: str = "",
        severity: str = "UNKNOWN",
        cwe: str = "",
    ) -> None:
        """
        Saves a structured Vulnerability → Fix pair to long-term memory.
        Future scans of similar code will recall this lesson.
        """
        if self.collection is None:
            return

        doc_id = str(uuid.uuid4())
        document_text = (
            f"[VULNERABILITY TYPE]: {vuln_type}\n"
            f"[SEVERITY]: {severity}\n"
            f"[CWE]: {cwe}\n"
            f"[DESCRIPTION]: {description}\n"
            f"[SOURCE FILE]: {file_path}\n"
            f"[SUCCESSFUL FIX PATTERN]:\n{fix_code[:2000]}"
        )

        try:
            self.collection.add(
                ids=[doc_id],
                documents=[document_text],
                metadatas=[{
                    "type": vuln_type,
                    "severity": severity,
                    "cwe": cwe,
                    "file": file_path,
                    "timestamp": datetime.datetime.utcnow().isoformat(),
                    "source": "learned",
                }],
            )
            logger.info("Knowledge base: memorised fix for '%s' in %s", vuln_type, file_path)
        except Exception as e:
            logger.warning("Failed to save lesson: %s", e)

    def learn_rejection(
        self,
        file_path: str,
        original_code: str,
        rejected_patch: str,
        feedback: str,
        vulnerabilities: list = None,
    ) -> None:
        """
        Saves a rejected patch as a negative example (anti-pattern) so the LLM
        learns what NOT to do when it encounters a similar vulnerability in the future.
        """
        if self.collection is None:
            return

        vuln_types = ""
        if vulnerabilities:
            try:
                vuln_types = ", ".join([
                    v.get("type", "") if isinstance(v, dict) else getattr(v, "type", "")
                    for v in vulnerabilities
                ])
            except Exception:
                pass

        doc_id = str(uuid.uuid4())
        # Truncate code snippets to keep document size manageable
        original_snippet = original_code[:500] if original_code else ""
        rejected_snippet = rejected_patch[:500] if rejected_patch else ""

        document_text = (
            f"[ANTI-PATTERN — REJECTED PATCH] DO NOT repeat this approach.\n"
            f"[FILE]: {file_path}\n"
            f"[VULNERABILITY TYPES]: {vuln_types}\n"
            f"[REJECTION REASON]: {feedback}\n"
            f"[ORIGINAL CODE SNIPPET]:\n{original_snippet}\n"
            f"[REJECTED PATCH SNIPPET]:\n{rejected_snippet}"
        )

        try:
            self.collection.add(
                ids=[doc_id],
                documents=[document_text],
                metadatas=[{
                    "type": "rejected_patch",
                    "severity": "UNKNOWN",
                    "file": file_path,
                    "feedback": feedback[:200],
                    "timestamp": datetime.datetime.utcnow().isoformat(),
                    "source": "rejection",
                }],
            )
            logger.info("Knowledge base: saved rejection anti-pattern for %s", file_path)
        except Exception as e:
            logger.warning("Failed to save rejection: %s", e)