from typing import Annotated, Literal

from fastapi import APIRouter, Body, HTTPException, Path, Query

from .. import repository
from ..schemas import RecordCreate, RecordRead, RecordReplace

router = APIRouter(prefix="/records", tags=["Записи"])

RecordId = Annotated[int, Path(gt=0, description="Ідентифікатор запису")]
NOT_FOUND = {404: {"description": "Запис або категорію не знайдено"}}
CONFLICT = {409: {"description": "Дублікат code"}}


@router.get("", response_model=list[RecordRead], summary="Список записів з фільтрами")
def list_records(
    category_id: Annotated[
        int | None, Query(gt=0, description="Лише записи категорії")
    ] = None,
    status: Annotated[
        Literal["new", "in_progress", "done"] | None,
        Query(description="Лише записи з цим статусом"),
    ] = None,
    min_value: Annotated[
        int | None, Query(ge=0, description="value >= min_value")
    ] = None,
    q: Annotated[
        str | None,
        Query(
            min_length=1,
            max_length=120,
            description="Підрядок у title (з урахуванням регістру)",
        ),
    ] = None,
    limit: Annotated[
        int, Query(ge=1, le=100, description="Макс. кількість записів")
    ] = 20,
    offset: Annotated[int, Query(ge=0, description="Скільки записів пропустити")] = 0,
):
    return repository.list_records(category_id, status, min_value, q, limit, offset)


@router.post(
    "/bulk",
    response_model=list[RecordRead],
    status_code=201,
    summary="Пакетне створення записів",
    responses={**NOT_FOUND, **CONFLICT},
)
def create_records_bulk(
    records: Annotated[list[RecordCreate], Body(min_length=1, max_length=100)],
):
    return repository.create_records([record.model_dump() for record in records])


@router.get(
    "/{record_id}", response_model=RecordRead, summary="Один запис", responses=NOT_FOUND
)
def get_record(record_id: RecordId):
    record = repository.get_record(record_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Запис не знайдено")
    return record


@router.post(
    "",
    response_model=RecordRead,
    status_code=201,
    summary="Створити запис",
    responses={**NOT_FOUND, **CONFLICT},
)
def create_record(record: RecordCreate):
    return repository.create_record(**record.model_dump())


@router.put(
    "/{record_id}",
    response_model=RecordRead,
    summary="Повна заміна запису",
    responses={**NOT_FOUND, **CONFLICT},
)
def replace_record(record_id: RecordId, record: RecordReplace):
    updated = repository.update_record(record_id, **record.model_dump())
    if updated is None:
        raise HTTPException(status_code=404, detail="Запис не знайдено")
    return updated


@router.delete(
    "/{record_id}", status_code=204, summary="Видалити запис", responses=NOT_FOUND
)
def delete_record(record_id: RecordId):
    if not repository.delete_record(record_id):
        raise HTTPException(status_code=404, detail="Запис не знайдено")
