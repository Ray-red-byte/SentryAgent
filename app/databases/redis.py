# app/databases/redis.py
import redis
import os

class RedisClientWrapper:
    _client = None

    @property
    def client(self):
        if self._client is None:
            host = os.getenv("REDIS_HOST", "localhost")
            port = int(os.getenv("REDIS_PORT", 6379))
            try:
                self._client = redis.Redis(
                    host=host,
                    port=port,
                    db=0,
                    decode_responses=True, # Returns strings instead of bytes
                    socket_connect_timeout=2
                )
                # Quick ping to check connection
                self._client.ping()
                print(f"✅ Connected to Redis at {host}:{port}")
            except redis.ConnectionError:
                print(f"⚠️ Warning: Redis at {host}:{port} is unreachable.")
                self._client = None # Handle gracefully in routes
        return self._client

# Singleton instance
redis_wrapper = RedisClientWrapper()

def get_redis():
    """
    Dependency to get the Redis client.
    Usage: client = get_redis()
    """
    return redis_wrapper.client