import hashlib
import logging
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from pymongo import MongoClient
from dotenv import load_dotenv
import os

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

# Initialize FastAPI
app = FastAPI()

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

## Route to register a new user (POST)
@app.post("/users/register")
async def register_user(user: User):
    # Check if the user already exists
    if users_collection.find_one({"userid": user.userid}):
        raise HTTPException(status_code=400, detail="User already exists")

    # Hash the password using SHA-256
    hashed_password = hash_password_sha256(user.password)

    # Create the user object
    new_user = {
        "userid": user.userid,
        "password": hashed_password,  # Store the hashed password
    }

    # Insert the user into the database
    result = users_collection.insert_one(new_user)

    logger.info(f"User {user.userid} registered successfully!")

    return {"message": "User registered successfully", "user_id": str(result.inserted_id)}


# Route to log in a user (POST)
@app.post("/users/login")
async def login_user(user: UserLogin):
    # Find the user in the database by userid
    db_user = users_collection.find_one({"userid": user.userid})
    
    if not db_user:
        raise HTTPException(status_code=400, detail="User not found")

    # Hash the provided password and compare it with the stored hashed password
    hashed_password = hash_password_sha256(user.password)

    if hashed_password != db_user["password"]:
        raise HTTPException(status_code=400, detail="Invalid credentials")

    # If the credentials are correct, log success
    logger.info(f"User {user.userid} logged in successfully!")

    # Return success response
    return {"message": "Login successful", "user_id": str(db_user["_id"])}
