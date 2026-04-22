import os
import networkx as nx
from pathlib import Path
from tree_sitter import Language, Parser
from app.core.parser.python_parser import PythonParser

class DependencyMapper(PythonParser):
    def __init__(self, root_dir: str):
        super().__init__()
        self.root_dir = Path(root_dir)
        self.graph = nx.DiGraph()
        
        self.import_query_scm = """
        (import_statement
            name: (_) @import_name
        )
        (import_from_statement
            module_name: (_) @from_import
        )
        """
        self.query = self.LANGUAGE.query(self.import_query_scm)

    def find_imports(self, source_code: bytes):
        """
        Extracts all imported modules from a file.
        Returns a list of module names (e.g., ['fastapi', 'app.core.config']).
        """
        # Parse the tree
        tree = self.parse(source_code)
        
        # Run the query
        matches = self.query.matches(tree.root_node)
        
        imports = set()
        
        for match in matches:
            captures = match.captures if hasattr(match, "captures") else match[1]
            
            # Helper to get text from a node
            def get_text(node):
                return source_code[node.start_byte:node.end_byte].decode('utf-8')

            # --- FIX: Helper to handle single Node vs List ---
            def get_captures_list(key):
                val = captures.get(key, [])
                if not isinstance(val, list):
                    return [val]
                return val
            # -----------------------------------------------

            # Process 'import x' or 'import x as y'
            for node in get_captures_list("import_name"):
                text = get_text(node)
                if " as " in text:
                    text = text.split(" as ")[0]
                imports.add(text.strip())
                
            # Process 'from x import ...'
            for node in get_captures_list("from_import"):
                text = get_text(node)
                imports.add(text.strip())
                
        return list(imports)

    def build_graph(self):
        """
        Scans the root_dir, parses every .py file, and builds the graph.
        """
        print(f"📂 Scanning directory: {self.root_dir.absolute()}")
        
        for file_path in self.root_dir.rglob("*.py"):
            if any(part.startswith(".") or part == "venv" or part == "__pycache__" for part in file_path.parts):
                continue
                
            relative_path = file_path.relative_to(self.root_dir)
            module_name = str(relative_path).replace(os.sep, ".").replace(".py", "")
            
            self.graph.add_node(module_name, filepath=str(file_path))
            
            try:
                with open(file_path, "rb") as f:
                    code = f.read()
                    if not code.strip():
                        continue
                        
                    found_imports = self.find_imports(code)
                    
                    for imp in found_imports:
                        if imp.startswith("app."):
                             self.graph.add_edge(module_name, imp)
                             
            except Exception as e:
                print(f"⚠️ Error parsing {file_path.name}: {e}")

        return self.graph