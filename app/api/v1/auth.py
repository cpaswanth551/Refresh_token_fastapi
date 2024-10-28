from datetime import timedelta
from typing import Annotated
from fastapi.security import OAuth2PasswordRequestForm
from jose import JWTError
from sqlalchemy.orm import Session
from fastapi import APIRouter, Depends, HTTPException, status

from app.core.auth import (
    autenticate_user,
    create_access_token,
    create_refresh_token,
    get_current_user,
    get_refresh_user,
)
from app.db.database import get_db
from app.db.models import User
from app.api.schemas import Token, UserInDB


router = APIRouter(prefix="/auth", tags=["auth"])


db_dependency = Annotated[Session, Depends(get_db)]
user_dependency = Annotated[dict, Depends(get_current_user)]


@router.get("/users/me", response_model=UserInDB)
async def read_users_me(db: db_dependency, current_user: user_dependency):
    user_id = current_user.get("id")
    return db.query(User).filter(User.id == user_id).first()


@router.post("/token/", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()], db: db_dependency
):

    autenticated_user = autenticate_user(form_data.username, form_data.password, db)
    if not autenticated_user:
        raise HTTPException(
            detail="could not validate user",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    autenticated_token = create_access_token(
        autenticated_user.username,
        autenticated_user.id,
        expires_delta=timedelta(minutes=29),
    )

    refresh_token = create_refresh_token(
        autenticated_user.username,
        autenticated_user.id,
        expires_delta=timedelta(days=10),
    )
    print(refresh_token)

    if not autenticated_token:
        raise HTTPException(
            detail="could not validate user",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    autenticated_user.refresh_token = refresh_token
    db.commit()

    return {
        "access_token": autenticated_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "data": {
            "username": autenticated_user.username,
            "id": autenticated_user.id,
        },
    }


@router.post("/refresh/", response_model=Token)
async def refresh_token(refresh_token: str, db: db_dependency):
    try:
        payload = await get_refresh_user(refresh_token)
        username = payload.get("sub")

        if username is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid refresh token"
            )

        user = db.query(User).filter(User.username == username).first()

        if not user or user.refresh_token != refresh_token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid refresh token"
            )

        autenticated_token = create_access_token(
            user.username,
            user.id,
            expires_delta=timedelta(minutes=29),
        )

        new_refresh_token = create_refresh_token(
            user.username,
            user.id,
            expires_delta=timedelta(days=10),
        )
        user.refresh_token = new_refresh_token
        db.commit()
        return {
            "access_token": autenticated_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "data": {
                "username": user.username,
                "id": user.id,
            },
        }

    except JWTError:
        raise HTTPException(status_code=401, detail="invalid refresh token")
