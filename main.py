#!/usr/bin/env python
# coding: utf-8




from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
## pydantic model for specify typer of acceptable data
from pydantic import BaseModel
from datetime import datetime, timedelta
## Jose - Related to tokens
from jose import JWTError, jwt
## Allow hashing of passwords
from passlib.context import CryptContext


## Created using openssl rand -hex 32
SECRET_KEY = "4be32616000e96c9d63d9b43e9512a65f249e07ff25516cb0097059967c29c57"
ALGORITHM = "HS256" # For hashing
ACCESS_TOKEN_EXPIRE_MINUTES = 30





db = {
    "shubh": {
        "username": "shubh812",
        "full_name": "Shubhashish Singh",
        "email" : "sss@gm.com",
        "hashed_password":"$2b$12$Vf2R8WaveGGYpMsX5pW9g.yXvSV7RHB.Vp8DdqDHI3dHW7.eD2OoK",
        "disabled":False
    }
}

class Token(BaseModel):
    access_token:str
    token_type:str

class TokenData(BaseModel):
    username: str or None = None

class User(BaseModel):
    username:str
    email:str or None=None
    full_name: str or None=None
    disabled:bool or None=None

class UserInDB(User):
    hashed_password: str


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth_2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(db, username: str):
    if username in db:
        user_data = db[username]
        ## pointer takes all data as key value parameters coz BaseModel doesnt accept JSON
        ## or dictionary
        return UserInDB(**user_data)
    
def authenticate_user(db, username: str, password: str):
    user = get_user(db, username)
    if not user: return False
    user.hashed_password = get_password_hash(password)
    print(password)
    if not verify_password(password, user.hashed_password): return False

    return user

def create_access_token(data: dict, expires_delta: timedelta or None=None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow()+expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


## Getting a user from access token

## Depends scheme parses out the token and give access to the parameter
async def get_current_user(token:str = Depends(oauth_2_scheme)):
    credential_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate Credentials", 
                                         headers={"WWW-Authenticate": "Bearer"})
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str=payload.get("sub")
        if username is None: 
            raise credential_exception

        token_data = TokenData(username=username)

    except JWTError:
        raise credential_exception
    

    user = get_user(db, username=token_data.username)
    if user is None: 
        raise credential_exception
    return user

# Preventing inactive user to log back in without authentication
# This can be done using get_current_user directly but this adds a Disabled property
# Whenever a user needs to be enabled or disabled
async def get_current_active_user(current_user: UserInDB = Depends(get_current_user)):
    if current_user.disabled: 
        raise HTTPException(status_code=400, detail="Inactive User")

    return current_user


## Actual Sign in with username and pw
@app.post("/token", response_model=Token)
# Here the depends is using the oathform to spcify the data to generate a JWTToken is
# gonna be a Username and password
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user: 
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, 
                                        detail="incorrect username or password", headers={"WWW-Authenticate": "Bearer"})
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}

# Authenticator roots- rely on the fact that we have signed in
@app.get("/users/me/", response_model=User)

async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user

@app.get("/users/me/items")
async def read_own_items(current_user: User = Depends(get_current_active_user)):
    return [{"item_id":1, "owner": current_user}]


# pwd = get_password_hash("ss1234")
# print(pwd)