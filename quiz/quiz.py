from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from typing import List, Union

from starlette import status

from quiz.schemas import QuizQuestion, QuizOption, QuizResponse, QuizDetails, Quizs, QuizAnsData, QuizOverview, \
    QuizQuestionInput, QuizAll
from sqlalchemy.orm import Session
from services import get_db
from quiz.models import QuizModel, Quiz_Overview, Quiz_Answer

route = APIRouter()


@route.get("/api/get_all_quiz/")
def get_all_quiz(user_id: str | None = None, db: Session = Depends(get_db)):
    if user_id is None:
        quiz_list = db.query(Quiz_Overview).all()
        quiz_all_resp = Quizs(quiz=[])
        for quiz in quiz_list:
            # print(quiz.is_active)
            quiz_details = QuizAll(id=quiz.id,
                                   name=quiz.name,
                                   total_time=quiz.total_time,
                                   pass_mark=quiz.pass_mark,
                                   desc=quiz.desc,
                                   is_active=quiz.is_active)
            quiz_all_resp.quiz.append(quiz_details)
        db.close()
        # return quiz_all_resp
        return quiz_all_resp
    else:
        print(user_id)
        quiz_list = db.query(Quiz_Overview).filter(Quiz_Overview.is_active == 1).all()
        quiz_all_resp = Quizs(quiz=[])
        for quiz in quiz_list:
            # print(quiz)
            quiz_answers = db.query(Quiz_Answer).filter(Quiz_Answer.quiz_id == quiz.id,
                                                        Quiz_Answer.uid == user_id).all()
            quiz_details = QuizDetails(
                id=quiz.id,
                name=quiz.name,
                total_time=quiz.total_time,
                pass_mark=quiz.pass_mark,
                desc=quiz.desc,
                is_active=quiz.is_active,
                quiz_answers=[qa.uid for qa in quiz_answers]  # Add UID from quiz answers
            )
            quiz_all_resp.quiz.append(quiz_details)

        db.close()
        return quiz_all_resp


@route.get("/api/quiz/{id}", response_model=QuizResponse)
def get_quiz(id: int, db: Session = Depends(get_db)):
    quiz_list = db.query(QuizModel).filter(QuizModel.quiz_id == id).all()
    db.close()

    # Convert QuizModel instances to the desired response structure
    quiz_response = QuizResponse(
        quiz=[
            QuizQuestion(
                questions=quiz.questions,
                answer=[
                    QuizOption(A=[quiz.option_a, int(quiz.option_a_correct)],
                               B=[quiz.option_b, int(quiz.option_b_correct)],
                               C=[quiz.option_c, int(quiz.option_c_correct)],
                               D=[quiz.option_d, int(quiz.option_d_correct)])
                ]
            )
            for quiz in quiz_list
        ]
    )

    return quiz_response


@route.post("/api/submitQuiz")
def submit_quiz(quiz_data: QuizAnsData, db: Session = Depends(get_db)):
    answer_detail = Quiz_Answer(quiz_id=quiz_data.quiz_id, uid=quiz_data.uid, answer=quiz_data.answer,
                                marks_obtained=quiz_data.marks_obtained, passed=quiz_data.passed
                                )
    try:
        db.add(answer_detail)
        db.commit()
        db.refresh(answer_detail)
        db.close()
        return {"msg": "Submitted Successfully"}
    except:
        return {"msg": "Error"}


@route.get("/api/quizReview/")
def quiz_review(quiz_id: int, userid: int, db: Session = Depends(get_db)):
    quiz_ans = db.query(Quiz_Answer).filter(Quiz_Answer.quiz_id == quiz_id, Quiz_Answer.uid == userid).first()
    if quiz_ans is None:
        return HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Could not find the Data",

        )
    else:
        return quiz_ans


@route.post("/api/createQuizOverview")
def create_quiz_overview(quizOverview: QuizOverview, db: Session = Depends(get_db)):
    quiz_overview = Quiz_Overview(name=quizOverview.name,
                                  total_time=quizOverview.total_time,
                                  pass_mark=quizOverview.pass_mark,
                                  desc=quizOverview.desc,
                                  is_active=quizOverview.is_active,
                                  quiz_start=quizOverview.quiz_start)
    print(quizOverview)
    try:
        db.add(quiz_overview)
        db.commit()
        db.refresh(quiz_overview)
        db.close()

    except:
        return HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Could not Upload the Data",
        )

    return HTTPException(
        status_code=status.HTTP_200_OK,
        detail="Upload Success",
        headers={"quizID": quiz_overview.id, "quizName": quiz_overview.name}
    )


@route.post("/api/add_quiz_question")
def add_quiz_question(quiz_question: QuizQuestionInput, db: Session = Depends(get_db)):
    if len(quiz_question.quiz_questions) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Data is empty"
        )

    else:
        try:
            for question_data in quiz_question.quiz_questions:
                question = QuizModel(
                    quiz_id=question_data.quiz_id,
                    questions=question_data.questions,
                    option_a=question_data.option_a,
                    option_b=question_data.option_b,
                    option_c=question_data.option_c,
                    option_d=question_data.option_d,
                    option_a_correct=question_data.option_a_correct,
                    option_b_correct=question_data.option_b_correct,
                    option_c_correct=question_data.option_c_correct,
                    option_d_correct=question_data.option_d_correct
                )
                db.add(question)
            db.commit()
            # return quiz_question.quiz_questions
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content={"detail": "Uploaded Successfully"}
            )
        except Exception as e:
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={"detail": "Error In Uploading"}
            )


@route.patch("/api/activate_quiz/")
def activate_quiz(quiz_id: int, toggleStatus: bool, db: Session = Depends(get_db)):
    try:
        item_data = db.query(Quiz_Overview).filter(Quiz_Overview.id == quiz_id).first()
        if toggleStatus:
            item_data.is_active = 1
            db.commit()
            db.refresh(item_data)
            db.close()
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content={"message": "activated"}
            )
        else:
            item_data.is_active = 0
            db.commit()
            db.refresh(item_data)
            db.close()
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content={"message": "deactivated"}
            )

        db.commit()
        db.refresh(item_data)
        db.close()
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"message": "success"}
        )
    except:
        return HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error While updating"
        )
