from sqlalchemy import Column, Integer, String, DateTime;
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class QuizModel(Base):
    __tablename__ = "quiz"
    sl_no = Column(Integer, autoincrement=True, primary_key=True, index=True)
    quiz_id = Column(Integer)
    questions = Column(String)
    option_a = Column(String)
    option_b = Column(String)
    option_c = Column(String)
    option_d = Column(String)
    option_a_correct = Column(Integer)
    option_b_correct = Column(Integer)
    option_c_correct = Column(Integer)
    option_d_correct = Column(Integer)


class Quiz_Overview(Base):
    __tablename__ = "quiz_overview"
    id = Column(Integer, autoincrement=True, primary_key=True, index=True)
    name = Column(String)
    total_time = Column(Integer)
    pass_mark = Column(Integer)
    desc = Column(String)
    is_active = Column(Integer)
    quiz_start = Column(DateTime)



class Quiz_Answer(Base):
    __tablename__ = "quiz_answer"
    id = Column(Integer, autoincrement=True, primary_key=True, index=True)
    quiz_id = Column(Integer)
    uid = Column(Integer)
    answer = Column(String)
    marks_obtained = Column(Integer)
    passed= Column(Integer)
