from datetime import datetime, timedelta, timezone
from uuid import uuid4

import jwt
from pwdlib import PasswordHash

passwords = PasswordHash.recommended()
# Equal-cost verification when a username does not exist.
DUMMY_HASH = passwords.hash("not-a-real-account-password")


def verify_password(password, stored_hash):
    return passwords.verify(password, stored_hash)


def issue_token(user, settings):
    now = datetime.now(timezone.utc)
    return jwt.encode({
        "sub": str(user["id"]), "iat": now,
        "exp": now + timedelta(minutes=settings.token_minutes),
        "iss": settings.jwt_issuer, "aud": settings.jwt_audience,
        "jti": str(uuid4()), "type": "access",
    }, settings.jwt_secret, algorithm="HS256")


def decode_token(token, settings):
    claims = jwt.decode(token, settings.jwt_secret, algorithms=["HS256"],
                        issuer=settings.jwt_issuer, audience=settings.jwt_audience,
                        options={"require": ["sub", "exp", "iat", "iss", "aud", "jti", "type"]})
    if claims["type"] != "access":
        raise jwt.InvalidTokenError("Wrong token type")
    return claims
