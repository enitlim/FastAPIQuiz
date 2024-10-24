from datetime import datetime
from typing import Dict, List, Union

from pydantic import BaseModel


class QuizOption(BaseModel):
    A: List[Union[str, int]]
    B: List[Union[str, int]]
    C: List[Union[str, int]]
    D: List[Union[str, int]]


class QuizQuestion(BaseModel):
    questions: str
    answer: List[QuizOption]


class QuizResponse(BaseModel):
    quiz: List[QuizQuestion]

class QuizAll(BaseModel):
    id: int
    name: str
    total_time: int
    pass_mark: int
    desc: str
    is_active: int
class QuizDetails(QuizAll):
    quiz_answers: List[int]


class Quizs(BaseModel):
    quiz: List[QuizDetails]


class QuizAnsData(BaseModel):
    quiz_id: int
    uid: int
    answer: str
    marks_obtained: int
    passed: int


class QuizReview(BaseModel):
    quiz_id: int
    uid: int
    answer: str
    marks_obtained: int


class QuizOverview(BaseModel):
    name: str
    total_time: int
    pass_mark: int
    desc: str
    is_active: int
    quiz_start:datetime

class QuizQuestionInsert(BaseModel):
    quiz_id: int
    questions: str
    option_a: str
    option_b: str
    option_c: str
    option_d: str
    option_a_correct: int
    option_b_correct: int
    option_c_correct: int
    option_d_correct: int


class QuizQuestionInput(BaseModel):
    quiz_questions: List[QuizQuestionInsert]
