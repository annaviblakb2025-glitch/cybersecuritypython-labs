from typing import Annotated

from fastapi import APIRouter, HTTPException, Path

from .. import repository
from ..schemas import CategoryCreate, CategoryRead

router = APIRouter(prefix="/categories", tags=["Категорії"])


@router.get("", response_model=list[CategoryRead], summary="Список категорій")
def list_categories():
    return repository.list_categories()


@router.post(
    "",
    response_model=CategoryRead,
    status_code=201,
    summary="Створити категорію",
    responses={409: {"description": "Категорія з такою назвою вже існує"}},
)
def create_category(category: CategoryCreate):
    return repository.create_category(category.name)


@router.delete(
    "/{category_id}",
    status_code=204,
    summary="Видалити порожню категорію",
    responses={
        404: {"description": "Категорію не знайдено"},
        409: {"description": "Категорія містить записи"},
    },
)
def delete_category(
    category_id: Annotated[int, Path(gt=0, description="Ідентифікатор категорії")],
):
    try:
        deleted = repository.delete_category(category_id)
    except ValueError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error
    if not deleted:
        raise HTTPException(status_code=404, detail="Категорію не знайдено")
