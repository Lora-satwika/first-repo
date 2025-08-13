from pydantic import BaseModel
from typing import Optional, Dict, Any
users_db = {}

class RegisterUser(BaseModel):
    username: str
    password: str
    email: str  

class LoginUser(BaseModel):
    username: str
    password: str

class UserProfile(BaseModel):
    username: str
    email: str
    login_access: int

class UserLogout(BaseModel):
    username: str
    password: str

class UserInDB(BaseModel):
    username: str
    email: str
    hashed_password: str
    login_access: int = 0
