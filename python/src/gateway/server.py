from fastapi import FastAPI, HTTPException, Header, Depends
import os
from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient
from auth import validate 
from auth_svc import access
from storage import util


load_dotenv()

app = FastAPI()

@app.get("/")
async def read_root():
    return {"Hello": "Welcome to Gateway-Microservice home page!"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080, reload=True)
