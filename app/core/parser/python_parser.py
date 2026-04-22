import tree_sitter_languages
from tree_sitter import Language, Parser

class PythonParser:
    def __init__(self):
        self.parser = tree_sitter_languages.get_parser('python')
        self.LANGUAGE = tree_sitter_languages.get_language('python')

    def parse(self, source_code: bytes):
        return self.parser.parse(source_code)

    def get_node_text(self, node, source_code: bytes):
        if not node:
            return None
        return source_code[node.start_byte:node.end_byte].decode('utf-8')

    def extract_params(self, function_node, source_code: bytes):
        params = []
        param_list_node = function_node.child_by_field_name('parameters')
        
        if not param_list_node:
            return params

        for child in param_list_node.children:
            if not child.is_named:
                continue

            arg_name = None
            arg_type = None

            if child.type == 'identifier':
                arg_name = self.get_node_text(child, source_code)
            elif child.type == 'typed_parameter':
                name_node = child.child_by_field_name('name')
                type_node = child.child_by_field_name('type')
                arg_name = self.get_node_text(name_node, source_code)
                arg_type = self.get_node_text(type_node, source_code)
            elif child.type == 'default_parameter':
                name_node = child.child_by_field_name('name')
                arg_name = self.get_node_text(name_node, source_code)
            elif child.type == 'typed_default_parameter':
                name_node = child.child_by_field_name('name')
                type_node = child.child_by_field_name('type')
                arg_name = self.get_node_text(name_node, source_code)
                arg_type = self.get_node_text(type_node, source_code)

            if arg_name:
                params.append({
                    "name": arg_name,
                    "type": arg_type or "Any"
                })
        return params
    
    def find_security_hotspots(self, source_code: bytes):
        tree = self.parse(source_code)
        query_scm = """
        (call
            function: [
                (attribute object: (identifier) @mod attribute: (identifier) @func)
                (identifier) @func
            ]
            (#match? @func "^(system|popen|run|call|execute|eval|exec|pickle|loads)$")
        ) @dangerous_call
        """
        query = self.LANGUAGE.query(query_scm)
        matches = query.matches(tree.root_node)
        
        hotspots = []
        for match in matches:
            captures = match.captures if hasattr(match, "captures") else match[1]
            # In tree-sitter 0.21.3, capture values are nodes directly, not lists
            node = captures.get("dangerous_call")
            if not node:
                continue
                
            code_snippet = self.get_node_text(node, source_code)
            # start_point is a tuple (row, column) in 0.21.3
            line_number = node.start_point[0] + 1
            
            risk_type = "Generic Risk"
            if "system" in code_snippet or "subprocess" in code_snippet: risk_type = "Command Injection Risk"
            elif "execute" in code_snippet: risk_type = "SQL Injection Risk"
            elif "eval" in code_snippet or "exec" in code_snippet: risk_type = "Code Injection Risk"
            
            hotspots.append({
                "type": risk_type,
                "line": line_number,
                "snippet": code_snippet,
                "severity": "HIGH"
            })
        return hotspots
    
    def find_entry_points(self, source_code: bytes):
        tree = self.parse(source_code)
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
        query = self.LANGUAGE.query(query_scm)
        matches = query.matches(tree.root_node)
        
        results = []
        for match in matches:
            captures = match.captures if hasattr(match, "captures") else match[1]
            
            # Check for missing nodes safely - in 0.21.3, values are nodes directly
            func_node = captures.get("func_name")
            if not func_node:
                continue
            func_name = self.get_node_text(func_node, source_code)
            
            method_node = captures.get("method_name")
            if not method_node:
                continue
            http_method = self.get_node_text(method_node, source_code).upper()
            
            func_def_node = captures.get("func_def")
            if not func_def_node:
                continue
            
            args = self.extract_params(func_def_node, source_code)
            
            results.append({
                "function": func_name,
                "method": http_method,
                "line": func_def_node.start_point[0] + 1,  # start_point is tuple in 0.21.3
                "args": args
            })
        return results