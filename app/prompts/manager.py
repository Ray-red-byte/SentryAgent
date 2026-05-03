import os
import yaml
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

class PromptManager:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(PromptManager, cls).__new__(cls)
            cls._instance.base_dir = Path(__file__).parent
            # Cache prompts in memory so we don't hit the disk on every call
            cls._instance._prompt_cache = {}
        return cls._instance

    def _read_and_parse_markdown(self, file_path: Path) -> dict:
        """Reads a markdown file, splits frontmatter and body."""
        if not file_path.exists():
            raise FileNotFoundError(f"CRITICAL: Prompt file not found at {file_path}")

        content = file_path.read_text(encoding='utf-8')
        metadata = {}
        body = content

        # Basic frontmatter parsing
        if content.startswith("---"):
            parts = content.split("---", 2)
            if len(parts) >= 3:
                try:
                    metadata = yaml.safe_load(parts[1]) or {}
                except yaml.YAMLError as e:
                    logger.warning(f"Failed to parse frontmatter in {file_path}: {e}")
                body = parts[2].strip()
        
        return {"metadata": metadata, "body": body}

    def get_prompt(self, key_path: str, **kwargs) -> str:
        """
        Fetches and formats a prompt from the markdown directory structure.
        Usage: pm.get_prompt("auditor.audit_with_cache", file_path="main.py")
        """
        # Convert "auditor.audit_with_cache" -> "auditor/audit_with_cache.md"
        parts = key_path.split('.')
        file_path = self.base_dir.joinpath(*parts).with_suffix('.md')

        # Use cached body if available, else read from disk
        if key_path not in self._prompt_cache:
            parsed = self._read_and_parse_markdown(file_path)
            self._prompt_cache[key_path] = parsed['body']
        
        prompt_template = self._prompt_cache[key_path]

        # Automatically inject common instructions if the template asks for them
        if "{common_instructions}" in prompt_template:
            if "common.security_persona" not in self._prompt_cache:
                common_path = self.base_dir / "common" / "security_persona.md"
                common_parsed = self._read_and_parse_markdown(common_path)
                self._prompt_cache["common.security_persona"] = common_parsed['body']
                
            kwargs['common_instructions'] = self._prompt_cache["common.security_persona"]

        # Format and return
        try:
            return prompt_template.format(**kwargs)
        except KeyError as e:
            raise ValueError(f"Missing variable for prompt '{key_path}': {e}")

    def get_metadata(self, key_path: str) -> dict:
        """Utility to fetch the YAML frontmatter for a specific prompt if needed."""
        parts = key_path.split('.')
        file_path = self.base_dir.joinpath(*parts).with_suffix('.md')
        parsed = self._read_and_parse_markdown(file_path)
        return parsed['metadata']