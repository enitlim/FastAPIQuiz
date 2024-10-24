from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
DATABASE_URL: str = "mysql+pymysql://root@localhost/misbackend"

engine = create_engine(DATABASE_URL)

SessionLocal = sessionmaker(autoflush=False, autocommit=False, bind=engine)
