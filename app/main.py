from fastapi import FastAPI

from app.db import models
from app.api.main import api_router
from app.db.database import engine

app = FastAPI()


@app.get("/heath-check")
def health_check():
    return {"message": "health site"}


app.include_router(api_router)

models.Base.metadata.create_all(bind=engine)
