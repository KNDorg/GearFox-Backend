import hashlib
import logging
import jwt  # Import PyJWT for JWT handling
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from pymongo import MongoClient
from dotenv import load_dotenv
from datetime import datetime, timedelta
import os
from fastapi.middleware.cors import CORSMiddleware

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# MongoDB connection
MONGO_URL = os.getenv("MONGO_URL")
client = MongoClient(MONGO_URL)
db = client["GearFox"]
users_collection = db["Users"]

# JWT settings
SECRET_KEY = os.getenv("SECRET_KEY", "your_secret_key")  # Use a strong secret key
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Initialize FastAPI
app = FastAPI()

# Configure CORS
origins = [
    "http://localhost:3000",  # Replace with your frontend URL
    "https://your-production-domain.com"  # Add your production domain if needed
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Models
class User(BaseModel):
    userid: str
    password: str

class UserLogin(BaseModel):
    userid: str
    password: str

# Helper function to hash passwords using SHA-256
def hash_password_sha256(password: str) -> str:
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

# Helper function to create a JWT token
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# JWT dependency to verify token
security = HTTPBearer()

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload  # Return the decoded token if valid
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Route to register a new user (POST)
@app.post("/users/register")
async def register_user(user: User):
    if users_collection.find_one({"userid": user.userid}):
        raise HTTPException(status_code=400, detail="User already exists")

    hashed_password = hash_password_sha256(user.password)
    new_user = {
        "userid": user.userid,
        "password": hashed_password,
    }

    result = users_collection.insert_one(new_user)
    logger.info(f"User {user.userid} registered successfully!")

    return {"message": "User registered successfully", "user_id": str(result.inserted_id)}

# Route to log in a user (POST)
@app.post("/users/login")
async def login_user(user: UserLogin):
    db_user = users_collection.find_one({"userid": user.userid})
    if not db_user:
        raise HTTPException(status_code=400, detail="User not found")

    hashed_password = hash_password_sha256(user.password)
    if hashed_password != db_user["password"]:
        raise HTTPException(status_code=400, detail="Invalid credentials")

    # Generate JWT token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.userid}, expires_delta=access_token_expires
    )

    logger.info(f"User {user.userid} logged in successfully!")
    return {"message": "Login successful", "access_token": access_token, "token_type": "bearer"}

# Example of a protected route
@app.get("/protected-route")
async def protected_route(token_data: dict = Depends(verify_token)):
    return {"message": "This is a protected route", "user": token_data["sub"]}
