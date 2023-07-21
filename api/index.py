import secrets
import jwt
from typing import Union
from typing import Annotated
from passlib.context import CryptContext
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel

app = FastAPI(docs_url="/api/docs", openapi_url="/api/openapi.json")

# Simulamos una base de datos con usuarios registrados
# En un entorno real, deberías almacenar las contraseñas en forma segura (hash)
# y obtener los datos de los usuarios de una base de datos.
USERS = {
    "karscxx@gmail.com": {
        "username": "karscxx@gmail.com",
        "password_hash": "$2b$12$CXPh9ZEhY9sdiEg95yFMBOEUFFUJBc.LVs8TdjATHX4k8F8d37gKG"  # Hash de "swordfish"
    }
}


# Configuramos el contexto de seguridad de PassLib
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

security = HTTPBasic()

class UserCredentials(BaseModel):
    username: str
    password: str

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def generate_jwt_token(data):
    secret_key = "mysecretkey"  # Reemplaza esto con una clave secreta fuerte
    return jwt.encode(data, secret_key, algorithm="HS256")

@app.get("/api/healthchecker")
def healthchecker():
    return {"status": "success", "message": "Integrate FastAPI Framework with Next.js"}


@app.post("/api/login")
def login(credentials: UserCredentials):
    current_username = credentials.username
    current_password = credentials.password

    user = USERS.get(current_username)
    if user is None or not verify_password(current_password, user["password_hash"]):
        raise HTTPException(
            status_code=401,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Basic"},
        )

    # Generar el JWT con la información del usuario que quieras incluir en el token
    jwt_payload = {"sub": user["username"]}
    jwt_token = generate_jwt_token(jwt_payload)

    return {"access_token": jwt_token, "token_type": "bearer"}


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class TodoCreate(BaseModel):
    title: str


class TodoUpdate(BaseModel):
    title: Union[str, None] = None
    completed: Union[bool, None] = None


class TodoItem(BaseModel):
    id: int
    title: str
    completed: bool


# Define the TodoItem model
class TodoItem(BaseModel):
    id: int
    title: str
    completed: bool


# In-memory storage for todo items
todos = []

# Route to create a new todo item


@app.post("/api/todos")
def create_todo_item(todo: TodoCreate):
    new_todo = TodoItem(id=len(todos) + 1, title=todo.title, completed=False)
    todos.append(new_todo)
    return new_todo

# Route to get all todo items


@app.get("/api/todos")
def get_all_todo_items():
    return todos

# Route to get a specific todo item by ID


@app.get("/api/todos/{todo_id}")
def get_todo_item(todo_id: int):
    for todo in todos:
        if todo.id == todo_id:
            return todo
    return {"error": "Todo item not found"}

# Route to update a specific todo item by ID


@app.patch("/api/todos/{todo_id}")
def update_todo_item(todo_id: int, todo: TodoUpdate):
    for todo_item in todos:
        if todo_item.id == todo_id:
            todo_item.title = todo.title if todo.title is not None else todo_item.title
            todo_item.completed = todo.completed if todo.completed is not None else todo_item.completed
            return todo_item
    return {"error": "Todo item not found"}

# Route to delete a specific todo item by ID


@app.delete("/api/todos/{todo_id}")
def delete_todo_item(todo_id: int):
    for i, todo_item in enumerate(todos):
        if todo_item.id == todo_id:
            del todos[i]
            return {"message": "Todo item deleted"}
    return {"error": "Todo item not found"}
