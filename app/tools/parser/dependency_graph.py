import os
import networkx as nx
from pathlib import Path
from tree_sitter import Query, QueryCursor
from app.tools.parser.python_parser import PythonParser

class DependencyMapper(PythonParser):
    def __init__(self, root_dir: str):
        super().__init__()
        self.root_dir = Path(root_dir)
        self.graph = nx.DiGraph()
        
        # FIX: Updated Query with correct node names for tree-sitter-python
        # 1. import_from_statement (was 'from_import_statement')
        # 2. We use 'name: (_)' to capture whatever is imported, whether it's a dotted_name or aliased_import
        self.import_query_scm = """
        (import_statement
            name: (_) @import_name
        )
        (import_from_statement
            module_name: (_) @from_import
        )
        """
        self.query = Query(self.LANGUAGE, self.import_query_scm)

    def find_imports(self, source_code: bytes):
        """
        Extracts all imported modules from a file.
        Returns a list of module names (e.g., ['fastapi', 'app.core.config']).
        """
        # Parse the tree
        tree = self.parse(source_code)
        
        # Run the query using a cursor
        cursor = QueryCursor(self.query)
        matches = cursor.matches(tree.root_node)
        
        imports = set()
        
        for match in matches:
            # Handle new match structure (object or tuple)
            captures = match.captures if hasattr(match, "captures") else match[1]
            
            # Helper to get text from a node
            def get_text(node):
                return source_code[node.start_byte:node.end_byte].decode('utf-8')

            # Process 'import x' or 'import x as y'
            for node in captures.get("import_name", []):
                text = get_text(node)
                # If it's "pandas as pd", we only want "pandas"
                if " as " in text:
                    text = text.split(" as ")[0]
                imports.add(text.strip())
                
            # Process 'from x import ...'
            for node in captures.get("from_import", []):
                text = get_text(node)
                # module_name usually doesn't have 'as', but let's be safe
                imports.add(text.strip())
                
        return list(imports)

    def build_graph(self):
        """
        Scans the root_dir, parses every .py file, and builds the graph.
        """
        print(f"📂 Scanning directory: {self.root_dir.absolute()}")
        
        # 1. Walk through all Python files
        for file_path in self.root_dir.rglob("*.py"):
            # Skip virtual envs, hidden files, or tests
            if any(part.startswith(".") or part == "venv" or part == "__pycache__" for part in file_path.parts):
                continue
                
            relative_path = file_path.relative_to(self.root_dir)
            # Convert path to python module format (app/api/main.py -> app.api.main)
            module_name = str(relative_path).replace(os.sep, ".").replace(".py", "")
            
            # Add the file as a Node in the graph
            self.graph.add_node(module_name, filepath=str(file_path))
            
            # 2. Parse imports
            try:
                with open(file_path, "rb") as f:
                    code = f.read()
                    # Skip empty files to avoid parsing errors
                    if not code.strip():
                        continue
                        
                    found_imports = self.find_imports(code)
                    
                    # 3. Add Edges (Connections)
                    for imp in found_imports:
                        # Heuristic: We only care about imports that look like they belong to our app.
                        # We verify if the import target exists in our graph or file structure.
                        
                        # In this simple version, we assume anything starting with "app." is internal.
                        if imp.startswith("app."):
                             self.graph.add_edge(module_name, imp)
                             
            except Exception as e:
                print(f"⚠️ Error parsing {file_path.name}: {e}")

        return self.graph

if __name__ == "__main__":
    # Test on the 'app' directory
    mapper = DependencyMapper("app") 
    graph = mapper.build_graph()
    
    print(f"\n✅ Graph Built: {len(graph.nodes)} Files, {len(graph.edges)} Connections")
    
    if len(graph.edges) > 0:
        print("\n🔗 Internal Connections Found:")
        for source, target in graph.edges:
            print(f"  [File: {source}] imports -> [{target}]")
    else:
        print("\n(No internal connections found yet. Ensure files use 'from app... import ...')")