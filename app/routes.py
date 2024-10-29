import hashlib
from fastapi import HTTPException
from pydantic import BaseModel
from . import app, logger
from .db import users_collection

# Modèles
class User(BaseModel):
    userid: str
    password: str

class UserLogin(BaseModel):
    userid: str
    password: str

# Fonction auxiliaire pour hasher les mots de passe avec SHA-256
def hash_password_sha256(password: str) -> str:
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

# Route pour créer un nouvel utilisateur (POST)
@app.post("/users")
async def create_user(user: User):
    # Vérifier si l'utilisateur existe déjà
    if users_collection.find_one({"userid": user.userid}):
        raise HTTPException(status_code=400, detail="User already exists")

    # Hasher le mot de passe avec SHA-256
    hashed_password = hash_password_sha256(user.password)

    # Créer l'objet utilisateur
    new_user = {
        "userid": user.userid,
        "password": hashed_password,  # Stocker le mot de passe hashé
    }

    # Insérer l'utilisateur dans la base de données
    result = users_collection.insert_one(new_user)

    logger.info(f"User {user.userid} created successfully!")

    return {"message": "User created successfully", "user_id": str(result.inserted_id)}

# Route pour connecter un utilisateur (POST)
@app.post("/users/login")
async def login_user(user: UserLogin):
    # Trouver l'utilisateur dans la base de données par userid
    db_user = users_collection.find_one({"userid": user.userid})
    
    if not db_user:
        raise HTTPException(status_code=400, detail="User not found")

    # Hasher le mot de passe fourni et le comparer avec le mot de passe stocké
    hashed_password = hash_password_sha256(user.password)

    if hashed_password != db_user["password"]:
        raise HTTPException(status_code=400, detail="Invalid credentials")

    # Si les identifiants sont corrects, loguer le succès
    logger.info(f"User {user.userid} logged in successfully!")

    # Retourner une réponse de succès
    return {"message": "Login successful", "user_id": str(db_user["_id"])}
