import os
from pathlib import Path
from tree_sitter import Language, Parser
from app.tools.parser.python_parser import PythonParser

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
        query_scm = """
        (class_definition) @class_def
        (decorated_definition) @decorated_def
        (function_definition) @func_def
        """
        
        query = self.LANGUAGE.query(query_scm)
        matches = query.matches(tree.root_node)
        
        chunks = []
        processed_ranges = set()

        def is_overlap(start, end):
            for p_start, p_end in processed_ranges:
                if start >= p_start and end <= p_end:
                    return True
            return False
        
        nodes_to_process = []
        for match in matches:
            captures = match.captures if hasattr(match, "captures") else match[1]
            
            for capture_name, capture_value in captures.items():
                # --- FIX START: Handle both List and Single Node ---
                # Tree-sitter 0.21+ returns a single Node, older versions return a list.
                if not isinstance(capture_value, list):
                    capture_value = [capture_value]
                # --- FIX END ---

                for node in capture_value:
                    nodes_to_process.append((node, capture_name))
        
        # Sort by length (descending) so we process biggest blocks (classes/decorated) first
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
            start_line = node.start_point[0] + 1 # .row is [0] in tuple
            
            # Identify the name (for metadata)
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