from datetime import datetime
from pydantic import BaseModel, ConfigDict, EmailStr


class UserBase(BaseModel):
    email: EmailStr
    username: str


class UserCreate(UserBase):
    password: str


class UserInDB(UserBase):
    id: int
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(orm_mode=True)


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str
    data: dict
