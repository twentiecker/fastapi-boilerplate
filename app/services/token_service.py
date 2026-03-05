from datetime import datetime
from fastapi import HTTPException, status
from jose import jwt, JWTError
from app.models.token_blacklist import TokenBlacklist
from app.core.config import settings


def blacklist_token(db, token: str, token_type: str):
    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
        exp = payload.get("exp")

    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )

    entry = TokenBlacklist(
        token=token,
        token_type=token_type,
        expired_at=datetime.fromtimestamp(exp),
    )

    db.add(entry)
    db.commit()
