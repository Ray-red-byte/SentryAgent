import chromadb
import os
from app.parser.chunker import CodeChunker

class CodebaseRAG:
    def __init__(self):
        # MICROSERVICES LOGIC:
        # Check if we are running in Docker (Env vars exist) or Local
        host = os.getenv("CHROMA_HOST", "localhost")
        
        # If running in Docker, the host is 'chromadb_server' (port 8000)
        # If running locally (outside docker), we hit localhost:8001
        port = 8000 if host == "chromadb_server" else 8001

        print(f"🔌 Connecting to ChromaDB at {host}:{port}...")
        
        # Use HttpClient to talk to the Docker Container
        self.client = chromadb.HttpClient(host=host, port=port)
        
        # Get/Create collection
        self.collection = self.client.get_or_create_collection(name="sentry_codebase")

    def ingest_codebase(self, root_dir: str):
        print(f"🚀 Starting Ingestion for: {root_dir}")
        chunker = CodeChunker(root_dir)
        chunks = chunker.process_directory()
        
        if not chunks:
            print("⚠️ No chunks found.")
            return

        ids = [c["id"] for c in chunks]
        documents = [c["text"] for c in chunks]
        metadatas = [c["metadata"] for c in chunks]

        self.collection.add(ids=ids, documents=documents, metadatas=metadatas)
        print(f"✅ Indexed {len(chunks)} items into ChromaDB Server.")

    def search(self, query: str, n_results=3):
        return self.collection.query(query_texts=[query], n_results=n_results)

if __name__ == "__main__":
    # Test logic
    try:
        rag = CodebaseRAG()
        rag.ingest_codebase("app")
        results = rag.search("health check")
        if results["documents"]:
            print(f"\n🎯 Match found: {results['metadatas'][0][0]['object_name']}")
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        print("💡 Hint: Did you run 'docker-compose up'?")