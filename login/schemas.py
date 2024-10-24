from pydantic import BaseModel
from typing import Optional


class User(BaseModel):
    uid: int
    email: Optional[str] = None
    fullname: Optional[str] = None
    role: str


class UserRegistration(User):
    password: str
