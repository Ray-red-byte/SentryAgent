from tree_sitter import Language, Parser, Query, QueryCursor
import tree_sitter_python as tspython

class PythonParser:
    def __init__(self):
        self.LANGUAGE = Language(tspython.language())
        self.parser = Parser(self.LANGUAGE)

    def parse(self, source_code: bytes):
        return self.parser.parse(source_code)

    def get_node_text(self, node, source_code: bytes):
        """Helper to get the string text of a node."""
        if not node:
            return None
        return source_code[node.start_byte:node.end_byte].decode('utf-8')

    def extract_params(self, function_node, source_code: bytes):
        """
        Manually walks the 'parameters' node to extract args and types.
        Handles:
          - def foo(x)
          - def foo(x: int)
          - def foo(x: int = 1)
        """
        params = []
        # 'parameters' is a named field in the python grammar
        param_list_node = function_node.child_by_field_name('parameters')
        
        if not param_list_node:
            return params

        for child in param_list_node.children:
            # Skip punctuation like "(" , ")" and ","
            if not child.is_named:
                continue

            arg_name = None
            arg_type = None

            # Case 1: Simple Identifier -> "user_id"
            if child.type == 'identifier':
                arg_name = self.get_node_text(child, source_code)

            # Case 2: Typed Parameter -> "user_id: int"
            elif child.type == 'typed_parameter':
                # The grammar usually has 'name' and 'type' fields
                name_node = child.child_by_field_name('name')
                type_node = child.child_by_field_name('type')
                arg_name = self.get_node_text(name_node, source_code)
                arg_type = self.get_node_text(type_node, source_code)

            # Case 3: Default Parameter -> "x=1"
            elif child.type == 'default_parameter':
                name_node = child.child_by_field_name('name')
                arg_name = self.get_node_text(name_node, source_code)

            # Case 4: Typed Default Parameter -> "x: int = 1"
            elif child.type == 'typed_default_parameter':
                name_node = child.child_by_field_name('name')
                type_node = child.child_by_field_name('type')
                arg_name = self.get_node_text(name_node, source_code)
                arg_type = self.get_node_text(type_node, source_code)

            if arg_name:
                params.append({
                    "name": arg_name,
                    "type": arg_type or "Any" # Default to Any if no type hint
                })
        
        return params
    
    def find_security_hotspots(self, source_code: bytes):
        """
        Scans for dangerous function calls and patterns (SAST Heuristics).
        Returns a list of 'Hotspots'.
        """
        tree = self.parse(source_code)
        
        # Heuristic Query: Find dangerous function calls
        query_scm = """
        (call
            function: [
                (attribute object: (identifier) @mod attribute: (identifier) @func)
                (identifier) @func
            ]
            (#match? @func "^(system|popen|run|call|execute|eval|exec|pickle|loads)$")
        ) @dangerous_call
        """
        
        query = Query(self.LANGUAGE, query_scm)
        cursor = QueryCursor(query)
        matches = cursor.matches(tree.root_node)
        
        hotspots = []
        
        for match in matches:
            # --- FIX: Handle Tree-Sitter 0.23+ Breaking Change ---
            # Old version returns object with .captures
            # New version returns tuple (match_id, captures_dict)
            captures = match.captures if hasattr(match, "captures") else match[1]
            
            nodes = captures.get("dangerous_call", [])
            if not nodes:
                continue
                
            node = nodes[0]
            
            # Extract the full text of the call
            code_snippet = self.get_node_text(node, source_code)
            line_number = node.start_point.row + 1
            
            # Classify the risk
            risk_type = "Generic Risk"
            if "system" in code_snippet or "subprocess" in code_snippet:
                risk_type = "Command Injection Risk"
            elif "execute" in code_snippet:
                risk_type = "SQL Injection Risk"
            elif "eval" in code_snippet or "exec" in code_snippet:
                risk_type = "Code Injection Risk"
            
            hotspots.append({
                "type": risk_type,
                "line": line_number,
                "snippet": code_snippet,
                "severity": "HIGH"
            })
            
        return hotspots
    
    def find_entry_points(self, source_code: bytes):
        tree = self.parse(source_code)
        
        # We capture both the method name (decorator) and the function definition
        query_scm = """
        (decorated_definition
            (decorator
                (call
                    function: (attribute
                        attribute: (identifier) @method_name
                    )
                )
            )
            definition: (function_definition
                name: (identifier) @func_name
            ) @func_def
            (#match? @method_name "^(get|post|put|delete|patch|options|head)$")
        )
        """
        
        query = Query(self.LANGUAGE, query_scm)
        cursor = QueryCursor(query)
        matches = cursor.matches(tree.root_node)
        
        results = []
        
        for match in matches:
            captures = match.captures if hasattr(match, "captures") else match[1]
            
            # 1. Get Function Name
            func_name_node = captures.get("func_name", [])[0]
            func_name = self.get_node_text(func_name_node, source_code)
            
            # 2. Get HTTP Method (e.g., 'get', 'post')
            method_node = captures.get("method_name", [])[0]
            http_method = self.get_node_text(method_node, source_code).upper()

            # 3. Get Function Definition Node (to extract params)
            func_def_node = captures.get("func_def", [])[0]
            
            # 4. Extract Parameters (The "Inputs")
            args = self.extract_params(func_def_node, source_code)
            
            results.append({
                "function": func_name,
                "method": http_method,
                "line": func_name_node.start_point.row + 1,
                "args": args
            })
                
        return results

if __name__ == "__main__":
    sample_code = """
from fastapi import FastAPI
from pydantic import BaseModel

class Item(BaseModel):
    name: str

app = FastAPI()

@app.get("/users/{user_id}")
def read_user(user_id: int, q: str | None = None):
    return {"user_id": user_id}

@app.post("/items/")
def create_item(item: Item, token: str = "abc"):
    save_to_db(item)
    """
    
    parser = PythonParser()
    try:
        routes = parser.find_entry_points(sample_code.encode('utf-8'))
        print(f"✅ Symbol Table Extracted ({len(routes)} routes):")
        import json
        print(json.dumps(routes, indent=2))
    except Exception as e:
        print(f"❌ Error: {e}")