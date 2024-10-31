from fastapi import FastAPI
from app.database import init_db
from app.routers import auth

app = FastAPI(title="FastAPI Starter", version="0.1.0", servers=[
    {"url": "http://localhost:8000", "description": "Development server"},
])

init_db()

app.include_router(auth.router, prefix="/auth", tags=["auth"])


@app.get("/")
def version():
    return {"version": app.version, "docs": "/docs"}
