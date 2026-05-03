import hashlib
import json

def fix_cache_key(session_id: str, file_path: str, vulnerabilities) -> str:
    """Cache key scoped to the exact vuln set — prevents one domain's patch being served to another."""
    sig = hashlib.md5(
        json.dumps(sorted(str(v) for v in (vulnerabilities or [])), sort_keys=True).encode()
    ).hexdigest()[:8]
    return f"fix_result:{session_id}:{file_path}:{sig}"