# app/databases/redis.py
import redis
import os
from app.config.settings import REDIS_HOST, REDIS_PORT
from app.utils.logger import get_logger

logger = get_logger(__name__)

class RedisClient:
    _client = None

    @property
    def client(self):
        if self._client is None:
            host = REDIS_HOST
            port = REDIS_PORT
            try:
                self._client = redis.Redis(
                    host=host,
                    port=port,
                    db=0,
                    decode_responses=True,
                    socket_connect_timeout=2
                )
                # Quick ping to check connection
                self._client.ping()
                logger.info("Connected to Redis at %s:%s", host, port)
            except redis.ConnectionError:
                logger.warning("Redis at %s:%s is unreachable.", host, port)
                self._client = None # Handle gracefully in routes
        return self._client

# Singleton instance
redis_client = RedisClient()

def get_redis():
    """
    Dependency to get the Redis client.
    Usage: client = get_redis()
    """
    return redis_client.client