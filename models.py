# models.py

from pydantic import BaseModel

# Model for user login (userid and password)
class UserLogin(BaseModel):
    userid: str
    password: str
