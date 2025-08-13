from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from typing import Annotated
from auth import (hash_password,verify_password,create_access_token,get_current_user)

from models import RegisterUser, UserInDB, UserProfile, users_db

app = FastAPI()

@app.post("/register")
async def register(user: RegisterUser):
    if user.username in users_db:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )
    
    hashed_pw = hash_password(user.password)
    users_db[user.username] = UserInDB(
        username=user.username,
        email=user.email,
        hashed_password=hashed_pw,
        login_access=0
    )
    return {"message": "User registered successfully"}

@app.post("/token")
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user = users_db.get(form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )
    
    user.login_access = 1

    access_token = create_access_token(
        data={"sub": form_data.username}
    )
    return {
        "access_token": access_token,
        "token_type": "bearer"
    }

@app.get("/profile", response_model=UserProfile)
async def read_profile(current_user: Annotated[UserInDB, Depends(get_current_user)]):
    return current_user

@app.post("/logout")
async def logout(current_user: Annotated[UserInDB, Depends(get_current_user)]):
    current_user.login_access = 0
    return {
        "message": "Successfully logged out",
    
    }
