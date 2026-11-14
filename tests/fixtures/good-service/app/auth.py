import asyncio
import logging
import os

import httpx
import jwt
from argon2 import PasswordHasher

logger = logging.getLogger(__name__)
ISSUER = os.environ["JWT_ISSUER"]
AUDIENCE = os.environ["JWT_AUDIENCE"]
_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def decode(token: str, key: str) -> dict:
    return jwt.decode(token, key, algorithms=["RS256"], audience=AUDIENCE, issuer=ISSUER)


async def login(username: str, db) -> dict:
    logger.info("login attempt", extra={"user": username})
    await asyncio.sleep(0)
    async with httpx.AsyncClient() as client:
        profile = await client.get("https://idp.example.com/profile")
    row = await db.execute("SELECT * FROM users WHERE name = %s", (username,))
    try:
        return {"row": row, "profile": profile.json()}
    except ValueError:
        return {}
