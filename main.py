
from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
import bcrypt
from jose import jwt
from datetime import datetime, timedelta
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import declarative_base, sessionmaker


# ---------------- DATABASE SETUP ----------------

DATABASE_URL = "sqlite:///./users.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()


class UserDB(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password = Column(String)


Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()


# ---------------- FASTAPI SETUP ----------------

app = FastAPI()


# ---------------- JWT SETUP ----------------

SECRET_KEY = "mysecretkey"
ALGORITHM = "HS256"

security = HTTPBearer()


# ---------------- TOKEN VERIFICATION ----------------

def verify_token(token: str):

    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )

        username = payload.get("username")

        return username

    except:
        return None


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    token = credentials.credentials

    username = verify_token(token)

    if username is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )

    return username


# ---------------- PYDANTIC MODELS ----------------

class User(BaseModel):
    username: str
    password: str


class LoginUser(BaseModel):
    username: str
    password: str


# ---------------- HOME ----------------

@app.get("/")
def home():
    return {
        "message": "Authentication API is running"
    }


# ---------------- REGISTER ----------------

@app.post("/register")
def register(
    user: User,
    db=Depends(get_db)
):

    existing_user = db.query(UserDB).filter(
        UserDB.username == user.username
    ).first()

    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="Username already exists"
        )

    hashed_password = bcrypt.hashpw(
        user.password.encode("utf-8"),
        bcrypt.gensalt()
    )

    new_user = UserDB(
        username=user.username,
        password=hashed_password.decode("utf-8")
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {
        "message": "User registered successfully",
        "username": user.username
    }


# ---------------- GET USERS ----------------

@app.get("/users")
def get_users(
    current_user=Depends(get_current_user),
    db=Depends(get_db)
):

    users = db.query(UserDB).all()

    return [
        {
            "id": user.id,
            "username": user.username
        }
        for user in users
    ]


# ---------------- DELETE USER ----------------

@app.delete("/users/{username}")
def delete_user(
    username: str,
    current_user=Depends(get_current_user),
    db=Depends(get_db)
):

    user = db.query(UserDB).filter(
        UserDB.username == username
    ).first()

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    db.delete(user)
    db.commit()

    return {
        "message": "User deleted successfully",
        "username": username
    }


# ---------------- UPDATE USER ----------------

@app.put("/users/{username}")
def update_user(
    username: str,
    user: User,
    current_user=Depends(get_current_user),
    db=Depends(get_db)
):

    existing_user = db.query(UserDB).filter(
        UserDB.username == username
    ).first()

    if not existing_user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    hashed_password = bcrypt.hashpw(
        user.password.encode("utf-8"),
        bcrypt.gensalt()
    )

    existing_user.username = user.username
    existing_user.password = hashed_password.decode("utf-8")

    db.commit()
    db.refresh(existing_user)

    return {
        "message": "User updated successfully",
        "username": existing_user.username
    }


# ---------------- LOGIN ----------------

@app.post("/login")
def login(
    user: LoginUser,
    db=Depends(get_db)
):

    existing_user = db.query(UserDB).filter(
        UserDB.username == user.username
    ).first()

    if not existing_user:
        return {
            "message": "User not found"
        }

    password_correct = bcrypt.checkpw(
        user.password.encode("utf-8"),
        existing_user.password.encode("utf-8")
    )

    if password_correct:

        token = jwt.encode(
            {
                "username": user.username
            },
            SECRET_KEY,
            algorithm=ALGORITHM
        )

        return {
            "message": "Login successful",
            "access_token": token
        }

    return {
        "message": "Incorrect password"
    }


# ---------------- PROFILE ----------------

@app.get("/profile")
def profile(
    current_user=Depends(get_current_user)
):

    return {
        "message": "Profile accessed successfully",
        "username": current_user
    }
