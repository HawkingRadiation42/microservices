from fastapi import FastAPI, HTTPException, Header, Depends
from pymongo import MongoClient
from pydantic import BaseModel
from passlib.context import CryptContext
import jwt
import datetime
import os

app = FastAPI()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class User(BaseModel):
    username: str
    password: str

def get_db():
    db_uri = os.environ.get("MONGODB_URI")
    db_name = os.environ.get("MONGODB_DB_NAME")
    if not (db_uri and db_name):
        raise HTTPException(status_code=500, detail="Database configuration missing")
    client = MongoClient(db_uri)
    db = client[db_name]
    return db

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

@app.post("/login")
def login(user: User):
    db = get_db()
    user_row = db.user.find_one({"email": user.username})

    if user_row:
        email = user_row["email"]
        hashed_password = user_row["password"]

        if not verify_password(user.password, hashed_password):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        return create_jwt(user.username, os.environ.get("JWT_SECRET"), True)
    else:
        raise HTTPException(status_code=401, detail="Invalid credentials")

@app.post("/validate")
def validate(authorization: str = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing credentials")

    encoded_jwt = authorization.split(" ")[1]

    try:
        decoded = jwt.decode(encoded_jwt, os.environ.get("JWT_SECRET"), algorithms=["HS256"])
    except:
        raise HTTPException(status_code=403, detail="Not authorized")

    return {"decoded": decoded}

def create_jwt(username, secret, authz):
    return jwt.encode(
        {
            "username": username,
            "exp": datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(days=1),
            "iat": datetime.datetime.utcnow(),
            "admin": authz
        },
        secret,
        algorithm="HS256"
    )

@app.get("/")
def read_root():
    return {"Hello": "Welcome to microservices auth home page!"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)
