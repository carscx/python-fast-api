from passlib.context import CryptContext

# Configuramos el contexto de seguridad de PassLib
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Contraseña a hashear
password = "12345678"

# Hash de la contraseña
hashed_password = pwd_context.hash(password)

print(f"Contraseña: {password}")
print(f"Hash de contraseña: {hashed_password}")