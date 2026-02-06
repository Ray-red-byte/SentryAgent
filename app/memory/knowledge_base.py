import chromadb
import os
import uuid
import datetime

class SecurityKnowledgeBase:
    def __init__(self):
        # Connect to the same ChromaDB instance
        host = os.getenv("CHROMA_HOST", "localhost")
        port = 8000 if host == "chromadb_server" else 8001
        self.client = chromadb.HttpClient(host=host, port=port)
        
        # New Collection specifically for "Learned Patterns"
        self.collection = self.client.get_or_create_collection(name="sentry_knowledge_base")

    def learn_fix(self, vuln_type: str, description: str, fix_code: str):
        """
        Saves a 'Vulnerability -> Fix' pair to long-term memory.
        """
        doc_id = str(uuid.uuid4())
        
        # We format the document so it's easy for the AI to understand later
        document_text = f"""
        [KNOWN VULNERABILITY TYPE]: {vuln_type}
        [DESCRIPTION]: {description}
        [SUCCESSFUL FIX PATTERN]:
        {fix_code}
        """
        
        self.collection.add(
            ids=[doc_id],
            documents=[document_text],
            metadatas=[{
                "type": vuln_type,
                "timestamp": str(datetime.datetime.now())
            }]
        )
        print(f"🧠 [Historian] Memorized new fix for: {vuln_type}")

    def recall_relevant_lessons(self, query_text: str, n_results=2):
        """
        Finds past lessons relevant to the current file/code.
        """
        try:
            results = self.collection.query(
                query_texts=[query_text], 
                n_results=n_results
            )
            
            lessons = []
            if results['documents']:
                for doc in results['documents'][0]:
                    lessons.append(doc)
            return lessons
        except Exception as e:
            print(f"⚠️ [Historian] Memory lookup failed: {e}")
            return []