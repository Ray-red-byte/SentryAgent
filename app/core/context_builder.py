import os
from pathlib import Path
from app.tools.parser.dependency_graph import DependencyMapper
from app.memory.vector_store import CodebaseRAG

class ContextAssembler:
    def __init__(self, root_dir: str):
        self.root_dir = Path(root_dir)
        self.mapper = DependencyMapper(root_dir)
        self.rag = CodebaseRAG() # Connects to Docker ChromaDB automatically

    def build_context_for_file(self, file_path: str):
        """
        Generates the full context needed for an AI to audit a specific file.
        Returns: A formatted string containing the Target File + Dependencies.
        """
        full_path = self.root_dir / file_path
        
        if not full_path.exists():
            return f"Error: File {file_path} not found."

        # 1. Read the Target File
        with open(full_path, "r") as f:
            target_code = f.read()

        # 2. Find what it imports (Using Task 4 Logic)
        # We read the raw bytes for tree-sitter
        imports = self.mapper.find_imports(target_code.encode('utf-8'))
        
        dependency_context = []
        
        print(f"🔍 Analyzing {file_path}...")
        print(f"   Found imports: {imports}")

        # 3. Fetch Dependency Code (Using Task 6 Logic)
        for imp in imports:
            # We search the Vector DB for the imported module/function name
            # Heuristic: We prefer exact matches on the 'object_name' metadata
            results = self.rag.search(imp, n_results=1)
            
            if results["documents"] and results["documents"][0]:
                code_snippet = results["documents"][0][0]
                source_file = results["metadatas"][0][0]["file_path"]
                
                # Only include if it's from our own codebase (not standard libs like os/json)
                if "app" in source_file: 
                    formatted_dep = f"\n--- DEPENDENCY: {imp} (from {source_file}) ---\n{code_snippet}\n"
                    dependency_context.append(formatted_dep)

        # 4. Assemble the Final Prompt
        final_context = "=== TARGET FILE TO AUDIT ===\n"
        final_context += f"Filename: {file_path}\n\n"
        final_context += target_code
        final_context += "\n\n=== EXTERNAL DEPENDENCIES (Context) ===\n"
        final_context += "\n".join(dependency_context)
        
        return final_context

if __name__ == "__main__":
    # Test: Let's build context for 'app/core/context_builder.py' (this file itself!)
    # It imports 'DependencyMapper' and 'CodebaseRAG', so we expect to see those codes included.
    
    assembler = ContextAssembler("app")
    
    # We need to target a file relative to the root 'app' dir in this specific setup logic
    # depending on how you mounted volumes. Let's try to target 'parser/chunker.py'
    # because we know it imports PythonParser.
    
    try:
        # Note: We run this INSIDE Docker, where /app/app exists
        ctx = assembler.build_context_for_file("parser/chunker.py")
        
        print("\n✅ GENERATED CONTEXT:\n")
        print(ctx[:1000]) # Print first 1000 chars
        print("\n... (truncated) ...")
    except Exception as e:
        print(f"❌ Error: {e}")