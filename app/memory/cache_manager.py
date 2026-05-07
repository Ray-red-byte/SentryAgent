import os
import datetime
from pathlib import Path
import google.generativeai as genai
from google.generativeai import caching
from app.utils.logger import get_logger
from app.config.settings import GEMINI_API_KEY

logger = get_logger(__name__)

# ── Noise filter sets ──────────────────────────────────────────────────────────
# Directories whose names cause os.walk to skip them entirely (in-place prune).
_SKIP_DIRS = frozenset({
    "test", "tests", "alembic", "versions", "migrations",
    "__pycache__", ".git", ".venv", "venv", "node_modules",
})
# Exact filenames to skip.
_SKIP_FILES = frozenset({"conftest.py", "seed.py", "seeds.py"})
# Filename prefixes/substrings that indicate dummy/mock data scripts.
# Using startswith/endswith guards to avoid false-positives like "smock.py".
_SKIP_SUBSTRINGS = ("mock_", "_mock", "test_", "_test", "fake_", "_fake")


def _is_noise_file(filename: str) -> bool:
    name = filename.lower()
    if name in _SKIP_FILES:
        return True
    return any(name.startswith(p) or name.endswith(p + ".py".replace(p, "")) for p in _SKIP_SUBSTRINGS)


class GeminiCacheManager:
    def __init__(self):
        self.api_key = GEMINI_API_KEY

        if not self.api_key:
            logger.critical("GEMINI_API_KEY is missing. Caching will fail.")
        else:
            genai.configure(api_key=self.api_key)

    def create_cache_for_session(
        self, session_id: str, root_dir: str, redis_client=None
    ) -> str:
        """
        Walks the session directory, aggregates production Python source code,
        and creates a Gemini Cache with a 15-minute TTL.

        Aggressively filters noise (tests, migrations, mocks, seeds) to stay
        below the 128k-token threshold that doubles the per-token price.

        If redis_client is provided, registers the cache name in the
        active_gemini_caches tracking set and writes the session cache key.
        """
        all_code_content = []
        skipped = 0

        logger.info("Packaging session %s for Gemini Cache...", session_id)

        for root, dirs, files in os.walk(root_dir):
            # Prune dirs in-place so os.walk never descends into noise folders.
            dirs[:] = [
                d for d in dirs
                if d.lower() not in _SKIP_DIRS and not d.startswith(".")
            ]

            # Also skip if a parent path component is a noise dir (belt-and-suspenders).
            rel_root = Path(root).relative_to(root_dir)
            if any(part.lower() in _SKIP_DIRS for part in rel_root.parts):
                skipped += len(files)
                continue

            for file in files:
                if not file.endswith(".py"):
                    continue
                if _is_noise_file(file):
                    skipped += 1
                    continue

                path = os.path.join(root, file)
                rel_path = os.path.relpath(path, root_dir)
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        content = f.read()
                    all_code_content.append(
                        f"\n\n<user_code file=\"{rel_path}\">\n{content}\n</user_code>\n"
                    )
                except Exception as e:
                    logger.warning("Skipping %s: %s", rel_path, e)

        if not all_code_content:
            raise ValueError("No eligible Python files found in this session.")

        file_count = len(all_code_content)
        logger.info(
            "Cache packaging: %d files included, %d noise files skipped.",
            file_count, skipped,
        )

        full_text = "".join(all_code_content)

        cache = caching.CachedContent.create(
            model="models/gemini-2.5-flash",
            display_name=f"session_{session_id}",
            system_instruction=(
                "You are a Senior Security Engineer. "
                "You have access to the full production codebase in this chat."
            ),
            contents=[full_text],
            ttl=datetime.timedelta(minutes=15),
        )

        if redis_client:
            redis_client.sadd("active_gemini_caches", cache.name)
            redis_client.setex(f"cache:{session_id}", 900, cache.name)

        logger.info("Cache created: %s (%d files)", cache.name, file_count)
        return cache.name

    def delete_cache(self, cache_name: str, redis_client=None) -> None:
        """
        Immediately destroys a Gemini Context Cache to stop idle storage billing.
        Safe to call even if the cache has already expired or been deleted.
        If redis_client is provided, removes the name from the tracking set.
        """
        try:
            caching.CachedContent.get(cache_name).delete()
            logger.info("Cache deleted: %s", cache_name)
            if redis_client:
                redis_client.srem("active_gemini_caches", cache_name)
        except Exception as e:
            logger.warning("Could not delete cache %s: %s", cache_name, e)

    def sweep_orphaned_caches(self, redis_client=None) -> None:
        """
        Deletes every Gemini cache registered in the active_gemini_caches Redis
        set. Called on startup (to clean crash survivors) and on shutdown (to
        prevent idle billing). Clears the tracking set after sweeping.
        """
        if redis_client is None:
            try:
                from app.databases.redis import get_redis
                redis_client = get_redis()
            except Exception as e:
                logger.warning("sweep_orphaned_caches: could not get Redis client: %s", e)
                return

        if not redis_client:
            return

        try:
            cache_names = redis_client.smembers("active_gemini_caches")
        except Exception as e:
            logger.warning("sweep_orphaned_caches: could not read tracking set: %s", e)
            return

        if not cache_names:
            logger.info("sweep_orphaned_caches: no orphaned caches found.")
            return

        logger.info("sweep_orphaned_caches: sweeping %d cache(s).", len(cache_names))
        for name in cache_names:
            try:
                caching.CachedContent.get(name).delete()
                logger.info("Orphaned cache deleted: %s", name)
            except Exception as e:
                logger.warning("Could not delete orphaned cache %s: %s", name, e)

        try:
            redis_client.delete("active_gemini_caches")
        except Exception as e:
            logger.warning("sweep_orphaned_caches: could not clear tracking set: %s", e)