import os
from pathlib import Path
from tree_sitter import Query, QueryCursor
from app.parser.python_parser import PythonParser

class CodeChunker(PythonParser):
    def __init__(self, root_dir: str):
        super().__init__()
        self.root_dir = Path(root_dir)

    def chunk_file(self, file_path: Path):
        """
        Reads a file and returns a list of "Chunks" (dictionaries).
        Each chunk contains: id, text, metadata.
        """
        with open(file_path, "rb") as f:
            code_bytes = f.read()

        tree = self.parse(code_bytes)
        
        # Query to capture generic functions and classes.
        # We use 'decorated_definition' to capture @decorators too.
        query_scm = """
        (class_definition) @class_def
        (decorated_definition) @decorated_def
        (function_definition) @func_def
        """
        
        query = Query(self.LANGUAGE, query_scm)
        cursor = QueryCursor(query)
        matches = cursor.matches(tree.root_node)
        
        chunks = []
        processed_ranges = set()

        # Helper to check if a node is already inside a larger chunk
        # (e.g., don't double-chunk a function if we already took the decorated version)
        def is_overlap(start, end):
            for p_start, p_end in processed_ranges:
                # If the new node is completely inside an existing one, skip it
                if start >= p_start and end <= p_end:
                    return True
            return False

        # We process matches. Note: tree-sitter matches might not be in order, 
        # but usually broad matches come before narrow ones in the list if structured right.
        # To be safe, we sort by start_byte to process top-down.
        
        nodes_to_process = []
        for match in matches:
            captures = match.captures if hasattr(match, "captures") else match[1]
            for capture_name, nodes in captures.items():
                for node in nodes:
                    nodes_to_process.append((node, capture_name))
        
        # Sort by length (descending) so we process biggest blocks (classes/decorated) first
        # This helps our deduplication logic.
        nodes_to_process.sort(key=lambda x: x[0].end_byte - x[0].start_byte, reverse=True)

        for node, type_name in nodes_to_process:
            start = node.start_byte
            end = node.end_byte
            
            if is_overlap(start, end):
                continue
            
            # Add to processed
            processed_ranges.add((start, end))
            
            # Extract text
            chunk_text = code_bytes[start:end].decode("utf-8")
            start_line = node.start_point.row + 1
            
            # Identify the name (for metadata)
            # Both class and function defs have a 'name' child
            name_node = node.child_by_field_name("name")
            
            # For decorated definitions, the name is inside the 'definition' child
            if not name_node and type_name == "decorated_def":
                def_node = node.child_by_field_name("definition")
                if def_node:
                    name_node = def_node.child_by_field_name("name")
            
            object_name = "unknown"
            if name_node:
                object_name = code_bytes[name_node.start_byte:name_node.end_byte].decode("utf-8")

            chunks.append({
                "id": f"{file_path.name}:{object_name}",
                "text": chunk_text,
                "metadata": {
                    "file_path": str(file_path),
                    "object_name": object_name,
                    "type": type_name,
                    "start_line": start_line
                }
            })
            
        return chunks

    def process_directory(self):
        """
        Walks the directory and chunks all python files.
        """
        all_chunks = []
        print(f"📦 Chunking codebase in: {self.root_dir}")
        
        for file_path in self.root_dir.rglob("*.py"):
            # Skip noise
            if "venv" in str(file_path) or "__pycache__" in str(file_path):
                continue
                
            try:
                file_chunks = self.chunk_file(file_path)
                all_chunks.extend(file_chunks)
                print(f"  - {file_path.name}: {len(file_chunks)} chunks")
            except Exception as e:
                print(f"  ⚠️ Failed to chunk {file_path.name}: {e}")
                
        return all_chunks

if __name__ == "__main__":
    # Self-test
    chunker = CodeChunker("app")
    chunks = chunker.process_directory()
    
    print(f"\n✅ Total Chunks Generated: {len(chunks)}")
    if chunks:
        print("\n--- Sample Chunk ---")
        print(f"Name: {chunks[0]['metadata']['object_name']}")
        print(f"Type: {chunks[0]['metadata']['type']}")
        print(f"Content:\n{chunks[0]['text'][:100]}...") # Show first 100 chars