# app/prompts/manager.py
import yaml
import os
from pathlib import Path

class PromptManager:
    _instance = None
    _prompts = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(PromptManager, cls).__new__(cls)
            cls._instance.load_prompts()
        return cls._instance

    def load_prompts(self):
        """
        Loads the hub.yaml relative to this python file.
        """
        # Get the directory of THIS file (app/prompts/)
        base_dir = Path(__file__).parent
        yaml_path = base_dir / "hub.yaml"

        try:
            with open(yaml_path, 'r', encoding='utf-8') as file:
                self._prompts = yaml.safe_load(file)
        except FileNotFoundError:
            raise FileNotFoundError(f"CRITICAL: Could not find prompt definitions at {yaml_path}")

    def get_prompt(self, key_path: str, **kwargs) -> str:
        """
        Fetches and formats a prompt.
        Usage: pm.get_prompt("auditor.audit_with_cache", file_path="main.py")
        """
        keys = key_path.split('.')
        value = self._prompts
        
        # 1. Traverse keys (auditor -> audit_with_cache)
        try:
            for k in keys:
                value = value[k]
        except KeyError:
            raise ValueError(f"Prompt key '{key_path}' not found in hub.yaml")

        # 2. Inject Common Persona automatically
        if "{common_instructions}" in value:
            common = self._prompts.get('common', {}).get('security_persona', '')
            kwargs['common_instructions'] = common

        # 3. Format
        try:
            return value.format(**kwargs)
        except KeyError as e:
            raise ValueError(f"Missing variable for prompt '{key_path}': {e}")