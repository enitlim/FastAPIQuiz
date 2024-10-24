from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class UserModel(Base):
    __tablename__ = "users"
    uid = Column(Integer, primary_key=True, index=True)
    username=Column(String(45))
    email = Column(String(45))
    fullname = Column(String(45))
    password = Column(String(45))
    role = Column(String(45))
