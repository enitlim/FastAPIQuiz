from sqlalchemy import Column, Integer, String, Date, TIMESTAMP
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class UserModel(Base):
    __tablename__ = "book"
    phpro_user_id = Column(Integer, primary_key=True, index=True)
    phpro_username = Column(String(40))
    phpro_password = Column(String(40))
    DESIGNATION = Column(String(20))
    GRADE = Column(String(20))
    DOB = Column(Date)
    BRCODE = Column(Integer)
    BRANCHNAME = Column(String(100))
    MOBILE = Column(String(50))
    DOJ = Column(Date)
    STATUS = Column(Integer)
    LEVEL = Column(Integer)
    DESIG_LEVEL = Column(Integer)
    PSW_SET = Column(Integer)
    PERMISSION = Column(Integer)
    pan = Column(String(10))
    aadhar = Column(String(12))
    permobile = Column(String(15))
    HOGroupId = Column(Integer)
    HOStaffGroupId = Column(Integer)
    UAN = Column(String(30))
    EMP_GENDER = Column(String(10))
    UPDATED_BY = Column(String(10))
    UPDATED_ON = Column(TIMESTAMP)
    CIF = Column(String(20))
    Educational_qualification = Column(String(255))
    JAIIB = Column(String(255))
    CAIIB = Column(String(255))
    EMAIL = Column(String(100))

