import os
import datetime
import google.generativeai as genai
from google.generativeai import caching
from app.utils.logger import get_logger

logger = get_logger(__name__)

class GeminiCacheManager:
    def __init__(self, api_key=None):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        
        if not self.api_key:
            logger.critical("GEMINI_API_KEY is missing. Caching will fail.")
        else:
            genai.configure(api_key=self.api_key)

    def create_cache_for_session(self, session_id: str, root_dir: str):
        """
        Walks the session directory, aggregates all Python code, 
        and creates a Gemini Cache with a 1-hour TTL.
        """
        all_code_content = []
        file_count = 0
        
        # 1. Walk the directory and collect code
        logger.info("Packaging session %s for Gemini Cache...", session_id)
        for root, _, files in os.walk(root_dir):
            for file in files:
                if file.endswith(".py"):
                    path = os.path.join(root, file)
                    # Create a relative path for the model to understand structure
                    rel_path = os.path.relpath(path, root_dir)
                    
                    try:
                        with open(path, "r", encoding="utf-8") as f:
                            content = f.read()
                            # Tagging the file so the model knows what it's looking at
                            tagged_content = f"\n\n<user_code file=\"{rel_path}\">\n{content}\n</user_code>\n"
                            all_code_content.append(tagged_content)
                            file_count += 1
                    except Exception as e:
                        logger.warning("Skipping %s: %s", rel_path, e)

        if not all_code_content:
            raise ValueError("No Python files found in this session.")

        # 2. Create the Cache
        # We use a huge context string. In production, you might upload file objects, 
        # but text concatenation is faster for <100 files.
        full_text = "".join(all_code_content)
        
        logger.info("Uploading %d files to Gemini Cache...", file_count)
        
        cache = caching.CachedContent.create(
            model='models/gemini-2.5-flash', # Must match the model used in Client
            display_name=f"session_{session_id}",
            system_instruction="You are a Senior Security Engineer. You have access to the full codebase in this chat.",
            contents=[full_text],
            ttl=datetime.timedelta(minutes=60),
        )
        
        logger.info("Cache created: %s", cache.name)
        return cache.name