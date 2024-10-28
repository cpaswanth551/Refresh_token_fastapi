from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.schemas import UserCreate, UserInDB
from app.core.auth import get_password_hash
from app.db.crud.users import create_user, get_all_users
from app.db.database import get_db
from app.db.models import User


router = APIRouter(prefix="/user", tags=["Users"])


@router.post("/register/", response_model=UserInDB)
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    return create_user(db, user)


@router.get("/all/", response_model=List[UserInDB])
def read_all(db: Session = Depends(get_db)):
    return get_all_users(db)



