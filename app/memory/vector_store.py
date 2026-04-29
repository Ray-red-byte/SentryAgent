import chromadb
import os
from app.core.parser.chunker import CodeChunker
from app.utils.logger import get_logger
from app.config.settings import CHROMA_HOST

logger = get_logger(__name__)

class CodebaseRAG:
    def __init__(self):
        host = CHROMA_HOST
        port = 8000 if host == "chromadb_server" else 8001
        logger.info("Connecting to ChromaDB at %s:%s...", host, port)
        
        # Use HttpClient to talk to the Docker Container
        self.client = chromadb.HttpClient(host=host, port=port)
        
        # Get/Create collection
        self.collection = self.client.get_or_create_collection(name="sentry_codebase")

    def ingest_codebase(self, root_dir: str):
        logger.info("Starting ingestion for: %s", root_dir)
        chunker = CodeChunker(root_dir)
        chunks = chunker.process_directory()
        
        if not chunks:
            logger.warning("No chunks found.")
            return

        ids = [c["id"] for c in chunks]
        documents = [c["text"] for c in chunks]
        metadatas = [c["metadata"] for c in chunks]

        self.collection.add(ids=ids, documents=documents, metadatas=metadatas)
        logger.info("Indexed %d items into ChromaDB Server.", len(chunks))

    def search(self, query: str, n_results=3):
        return self.collection.query(query_texts=[query], n_results=n_results)