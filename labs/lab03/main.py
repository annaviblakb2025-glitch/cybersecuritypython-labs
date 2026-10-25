import logging
import sqlite3
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from shared import student

from . import config
from .database import initialize_database
from .repository import CategoryNotFoundError
from .routers import categories, records

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    initialize_database()
    yield


app = FastAPI(
    title="Облік подій поштової безпеки",
    description=(
        f"{config.SUBJECT}. Кожен запис – спостереження: value = кількість "
        f"виявлених подій ({config.UNIT}), поріг {config.THRESHOLD}. "
        "Навчальні дані."
    ),
    lifespan=lifespan,
)
app.include_router(categories.router)
app.include_router(records.router)


@app.exception_handler(CategoryNotFoundError)
def category_not_found(request: Request, error: CategoryNotFoundError):
    return JSONResponse(status_code=404, content={"detail": str(error)})


@app.exception_handler(sqlite3.IntegrityError)
def integrity_error(request: Request, error: sqlite3.IntegrityError):
    logger.error("Помилка цілісності: %s", error)
    return JSONResponse(
        status_code=409,
        content={"detail": "Конфлікт даних: дублікат або порушення обмежень."},
    )


@app.exception_handler(sqlite3.Error)
def database_error(request: Request, error: sqlite3.Error):
    logger.error("Помилка бази даних: %s", error)
    return JSONResponse(
        status_code=500, content={"detail": "Внутрішня помилка сервера."}
    )


@app.get("/ping", summary="Перевірка доступності API")
def ping() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/student", summary="Студент")
def get_student() -> dict:
    return {
        "student_name": student.STUDENT_NAME,
        "group_name": student.GROUP_NAME,
        "variant_number": student.VARIANT_NUMBER,
    }
