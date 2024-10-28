from sqlite3 import IntegrityError
from fastapi import HTTPException, status

from app.core.auth import get_password_hash
from app.db.models import User


def create_user(db, user):
    try:
        db_user = db.query(User.email == user.email).first()
        if db_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Email already exists."
            )

        hashed_password = get_password_hash(user.password)

        db_user = User(
            email=user.email, username=user.username, hashed_password=hashed_password
        )
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        return db_user
    except IntegrityError as e:
        db.rollback()
        print(f"IntegrityError: {e}")
        raise HTTPException(
            status_code=400, detail="User with this email or username already exists"
        )

    except Exception as e:
        db.rollback()
        print(f"Unexpected error: {e}")
        raise HTTPException(status_code=500, detail="user is not created")


def get_all_users(db):
    try:
        return db.query(User).all()
    except Exception as e:
        print(f"Unexpected error: {e}")
        raise HTTPException(status_code=500, detail="users couldnot retrieved.")
