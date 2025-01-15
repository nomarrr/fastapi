from conexion import *
from fastapi import FastAPI, Depends, HTTPException, status, Form, File, UploadFile, Response
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError
import bcrypt
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timedelta
import os
import shutil
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional
import json



app = FastAPI()
oauth2 = OAuth2PasswordBearer(tokenUrl = "login")
ALGORITHM = "HS256"
SECRET = "JDFBGERGH9H9h93G4sf0N672S"
# ... imports existentes ...

origins = [
    "http://localhost:4200",
    "https://localhost:4200",
    "http://localhost:8000",
    "https://localhost:8000",
    "https://fastapi-production-6897.up.railway.app",
    "https://nomarrr.github.io",
    "http://nomarrr.github.io"  # Agregado para manejar redirecciones
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=3600
)

# ... resto del código ...
UPLOAD_FOLDER = "exerciseImg"
UPLOAD_FOLDER2 = "profileImages"
UPLOAD_FOLDER_RECIPES = "recipeImages"
app.mount("/exerciseImg", StaticFiles(directory="exerciseImg"), name="exerciseImg")
app.mount("/profileImages", StaticFiles(directory="profileImages"), name="profileImages")
app.mount("/recipeImages", StaticFiles(directory="recipeImages"), name="recipeImages")




def auth_user_role(token: str = Depends(oauth2)):
    exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="Invalid autenthentication credentials",
                                headers={"WWW-Authenticate": "Bearer"})
    try:
        role = jwt.decode(token, SECRET,algorithms=[ALGORITHM]).get("user_role")
        if role is None:
            raise exception
    except JWTError:
        raise exception
    return  role

def auth_user_id(token: str = Depends(oauth2)):
    exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="Invalid autenthentication credentials",
                                headers={"WWW-Authenticate": "Bearer"})
    try:
        id = jwt.decode(token, SECRET,algorithms=[ALGORITHM]).get("user_id")
        if id is None:
            raise exception
    except JWTError:
        raise exception
    return  id

@app.post("/register/")
async def register(name:str = Form(...),
        email:str= Form(...),
        password:str= Form(...)):
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    if add_user(name,email,hashed_password):
        return {"message": "user registered sucsesfully"}
    else:
        raise HTTPException(status_code=400, detail="email already in use")

@app.post("/login/")
async def login(form: OAuth2PasswordRequestForm = Depends()):
    if not validate_email(form.username):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="unregistered user")

    if not validate_password(form.password,form.username):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid password")

    access_token = {
        "user_id": get_user_id(form.username),
        "user_role": get_user_role(form.username),
        "exp": datetime.utcnow() + timedelta(days=7),
        "iat": datetime.utcnow(),
    }

    return {"access_token": jwt.encode(access_token, SECRET ,algorithm=ALGORITHM) , "token_type": "bearer"}

@app.put("/update_password/")
async def update_password(id:int = Depends(auth_user_id),
                          current_password:str = Form(...),
                          new_password:str = Form(...)):
    #print(id)
    hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    if validate_password(current_password, id):
        if update_passwordDB(id, hashed_password):
            return {"message": "password updated sucsesfully"}
        else:
            return {"message": "an error has ocurred"}
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid password")

@app.get("/get_users/")
async def get_users(role:int = Depends(auth_user_role)):
    if(role == 3):
        users = get_usersDB()
        return users
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="unauthorized user")

@app.delete("/delete_user/")
async def delete_user(role:int = Depends(auth_user_role),
                      id: str = Form()):
    if role == 3:
        if delete_client(id):
            return {"message": "user deleted sucsesfully"}
        else:
            return {"message": "an error has ocurred"}
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="unauthorized user")


@app.post("/create-routine/")
async def create_routine(
    routine_data: dict,
    coach_id: int = Depends(auth_user_id),
    role: int = Depends(auth_user_role),
):
    """
    Endpoint para crear una rutina y asociar ejercicios a ella.
    """
    if role != 2:  # Verifica que el usuario sea un coach
        raise HTTPException(status_code=403, detail="Unauthorized")

    # Validar formato de rutina
    required_keys = {"name", "exercises"}
    if not required_keys.issubset(routine_data.keys()):
        raise HTTPException(status_code=400, detail="Missing required fields: 'name' and 'exercises'")

    if not isinstance(routine_data["exercises"], list):
        raise HTTPException(status_code=400, detail="Field 'exercises' must be a list")

    # Llamar a la función para crear la rutina
    try:
        response = create_routine_in_db(routine_data, coach_id)
        return response
    except HTTPException as http_err:
        raise http_err
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred: {e}")


@app.get("/users/{id}/routines/")
async def get_users_routines(id: int):
    # Llama a la función que obtiene las rutinas del usuario desde la base de datos
    user_routines = get_user_routines(id)
    return user_routines

@app.get("/routines/{routine_id}/exercises/")
async def get_routine_exercises(routine_id: int):
    routine_exercises = get_routine_exercisesDB(routine_id)
    return routine_exercises

@app.get("/muscle_groups/")
async def get_musclular_groups():
    muscle_gorups = get_muscle_groups()
    return muscle_gorups


@app.post("/create-exercise/")
async def create_exercise(
        name: str = Form(...),
        description: str = Form(...),
        muscle_group_id: int = Form(...),
        image: UploadFile = File(...),
        coach_id: int = Depends(auth_user_id),
        role: int = Depends(auth_user_role)
):
    if role != 2:  # Verifica que el usuario sea un coach
        raise HTTPException(status_code=403, detail="Unauthorized")

    try:
        # Genera un nombre único para el archivo
        file_extension = os.path.splitext(image.filename)[1]
        unique_filename = f"exercise_{datetime.now().strftime('%Y%m%d_%H%M%S')}{file_extension}"

        # Guarda el archivo en la carpeta especificada
        file_path = os.path.join(UPLOAD_FOLDER, unique_filename)
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(image.file, buffer)

        # La ruta que se guardará en la base de datos
        db_image_path = f"http://127.0.0.1:8000/exerciseImg/{unique_filename}"

        # Guarda el ejercicio en la base de datos con la ruta de la imagen
        if add_exercise(name, description, muscle_group_id, db_image_path):
            return {"message": "Exercise created successfully"}
        else:
            # Si falla la inserción en la BD, elimina la imagen guardada
            os.remove(file_path)
            raise HTTPException(status_code=400, detail="An error occurred while creating the exercise")

    except Exception as e:
        # Manejo de errores
        print(f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")


@app.get("/exercises/muscle_group/{muscle_group_id}")
async def get_exercises_by_muscle_group(
        muscle_group_id: int,
        token: str = Depends(oauth2)
):
    try:
        # Obtén los ejercicios asociados al grupo muscular
        exercises = get_exercises_by_muscle_group_id(muscle_group_id)
        return exercises
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/coach-routines")
async def get_coach_routines(coach_id: int = Depends(auth_user_id)):
    """
    Endpoint para obtener las rutinas de un coach autenticado.
    """
    try:
        routines = fetch_coach_routines_from_db(coach_id)
        return routines
    except Exception:
        raise HTTPException(status_code=500, detail="Internal server error")


@app.get("/routines/{routine_id}")
async def get_routine(routine_id: int, user_id: int = Depends(auth_user_id)):
    """
    Endpoint para obtener una rutina y sus ejercicios.

    Args:
        routine_id (int): ID de la rutina a consultar.
        user_id (int): ID del usuario autenticado (extraído de la dependencia).

    Returns:
        dict: Detalles de la rutina con sus ejercicios.

    Raises:
        HTTPException: En caso de errores, como rutina no encontrada o acceso no autorizado.
    """
    try:
        print(f"Verificando acceso del usuario {user_id} para la rutina {routine_id}")

        # Llamar a la función con la rutina y el coach_id
        routine = fetch_routine_with_exercises(routine_id, user_id)

        if routine is None:
            print(f"Rutina {routine_id} no encontrada.")
            raise HTTPException(status_code=404, detail="Routine not found")

        print(f"Usuario {user_id} autorizado para acceder a la rutina {routine_id}.")
        return routine

    except HTTPException as http_err:
        # Re-lanzar excepciones HTTP específicas
        print(f"Error HTTP en el endpoint GET /routines/{routine_id}: {http_err.detail}")
        raise http_err
    except Exception as e:
        # Capturar y manejar errores generales
        print(f"Error inesperado en el endpoint GET /routines/{routine_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


from fastapi import APIRouter, HTTPException, Depends


@app.put("/routines/{routine_id}/exercises")
async def update_routine_exercises(
        routine_id: int,
        data: dict,
        coach_id: int = Depends(auth_user_id),
        role: int = Depends(auth_user_role),
):
    """
    Endpoint para actualizar los ejercicios de una rutina.

    Args:
        routine_id (int): ID de la rutina a actualizar.
        data (dict): JSON con el nombre de la rutina y los ejercicios.
        coach_id (int): ID del coach autenticado (obtenido desde la dependencia).
        role (int): Rol del usuario autenticado.
    """
    print(f"Coach ID: {coach_id}, Role: {role}, Routine ID: {routine_id}")
    print(f"Data received: {data}")

    # Verificar que el usuario tenga el rol de coach
    if role != 2:
        print("Unauthorized: User is not a coach.")
        raise HTTPException(status_code=403, detail="Unauthorized")

    # Verificar que el coach sea dueño de la rutina
    if not fetch_routine_ownership_from_db(routine_id,coach_id):
        print("Unauthorized: Coach does not own the routine.")
        raise HTTPException(status_code=403, detail="You do not have permission to edit this routine")

    # Validar que el JSON contiene los campos necesarios
    required_keys = {"name", "exercises"}
    if not required_keys.issubset(data.keys()):
        print("Invalid request: Missing required keys in the payload.")
        raise HTTPException(status_code=400, detail="Missing required fields: 'name' and 'exercises'")

    # Agregar el ID de la rutina al payload para la función de actualización
    data["routine_id"] = routine_id

    try:
        # Actualizar la rutina en la base de datos
        update_routine(data)
        print(f"Routine {routine_id} successfully updated by coach {coach_id}.")
        return {"message": "Routine updated successfully"}
    except Exception as e:
        print(f"Error updating routine {routine_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to update routine")

    # Resto de la lógica...

@app.delete("/routines/{routine_id}")
async def delete_routine(
    routine_id: int,
    coach_id: int = Depends(auth_user_id),
    role: int = Depends(auth_user_role)
):
    """
    Endpoint para eliminar una rutina y sus ejercicios asociados.
    """
    print(f"Intento de eliminación - Routine ID: {routine_id}, Coach ID: {coach_id}, Role: {role}")  # Log de debugging

    # Verificar que el usuario sea un coach
    if role != 2:
        print(f"Error: Usuario con rol {role} intentó eliminar rutina")  # Log de debugging
        raise HTTPException(status_code=403, detail="Unauthorized: User is not a coach")

    # Verificar que el coach sea dueño de la rutina
    is_owner = fetch_routine_ownership_from_db(routine_id, coach_id)
    print(f"Verificación de propiedad: {is_owner}")  # Log de debugging

    if not is_owner:
        print(f"Error: Coach {coach_id} intentó eliminar rutina {routine_id} sin ser propietario")  # Log de debugging
        raise HTTPException(
            status_code=403, 
            detail="Unauthorized: You don't have permission to delete this routine"
        )

    # Intentar eliminar la rutina y sus ejercicios
    if delete_routine_and_exercises(routine_id):
        return {"message": "Routine and associated exercises deleted successfully"}
    else:
        raise HTTPException(
            status_code=500,
            detail="An error occurred while deleting the routine"
        )

@app.get("/coach/clients")
async def get_clients(
    coach_id: int = Depends(auth_user_id),
    role: int = Depends(auth_user_role)
):
    """
    Endpoint para obtener todos los clientes asignados a un coach.
    
    Returns:
        list: Lista de clientes con su id, nombre e imagen
    """
    # Verificar que el usuario sea un coach
    if role != 2:
        raise HTTPException(
            status_code=403, 
            detail="Unauthorized: User is not a coach"
        )
    
    try:
        clients = get_coach_clients(coach_id)
        return clients
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail="Error retrieving clients"
        )

@app.get("/coach/clients/workouts")
async def get_clients_workout_info(
    token: str = Depends(oauth2),
    coach_id: int = Depends(auth_user_id),
    role: int = Depends(auth_user_role)
):
    """
    Endpoint para obtener información de entrenamientos de todos los clientes,
    indicando si el coach es responsable de cada uno.
    Requiere autenticación y rol de coach.
    
    Returns:
        list: Lista de clientes con su información y si el coach es responsable
    """
    # Verificar que el usuario sea un coach
    if role != 2:
        raise HTTPException(
            status_code=403, 
            detail="Unauthorized: User is not a coach"
        )
    
    try:
        clients = get_clients_workouts_with_responsibility(coach_id)
        return clients
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail="Error retrieving clients workout information"
        )

@app.get("/coach-view-client/{client_id}")
async def get_client_workout_info(
    client_id: int,
    token: str = Depends(oauth2),
    coach_id: int = Depends(auth_user_id),
    role: int = Depends(auth_user_role)
):
    """
    Endpoint para obtener información de entrenamientos de un cliente específico,
    indicando si el coach es responsable.
    Requiere autenticación y rol de coach.
    
    Args:
        client_id (int): ID del cliente a consultar
    
    Returns:
        dict: Información del cliente y si el coach es responsable
    """
    # Verificar que el usuario sea un coach
    if role != 2:
        raise HTTPException(
            status_code=403, 
            detail="Unauthorized: User is not a coach"
        )
    
    try:
        client = get_client_workout_info_by_id(client_id, coach_id)
        if client is None:
            raise HTTPException(
                status_code=404,
                detail="Client not found"
            )
        return client
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail="Error retrieving client workout information"
        )

@app.post("/coach/assign-client/{client_id}")
async def assign_client(
    client_id: int,
    token: str = Depends(oauth2),
    coach_id: int = Depends(auth_user_id),
    role: int = Depends(auth_user_role)
):
    """
    Endpoint para que un coach se asigne como responsable de un cliente.
    Requiere autenticación y rol de coach.
    
    Args:
        client_id (int): ID del cliente a asignar
        
    Returns:
        dict: Mensaje de éxito o error
    """
    # Verificar que el usuario sea un coach
    if role != 2:
        raise HTTPException(
            status_code=403, 
            detail="Unauthorized: User is not a coach"
        )
    
    try:
        result = assign_coach_to_client(coach_id, client_id)
        
        if not result["success"]:
            if "not found" in result["message"]:
                raise HTTPException(status_code=404, detail=result["message"])
            elif "already responsible" in result["message"]:
                raise HTTPException(status_code=400, detail=result["message"])
            else:
                raise HTTPException(status_code=400, detail=result["message"])
                
        return {"message": result["message"]}
        
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail="Error assigning coach to client"
        )

@app.delete("/users/{client_id}/routines/{routine_id}")
async def unassign_routine(
    client_id: int,
    routine_id: int,
    coach_id: int = Depends(auth_user_id),
    role: int = Depends(auth_user_role)
):
    """
    Endpoint para desasignar una rutina de un cliente.
    Solo puede ser ejecutado por un coach y debe ser el responsable del cliente.
    
    Args:
        client_id (int): ID del cliente
        routine_id (int): ID de la rutina a desasignar
        
    Returns:
        dict: Mensaje de éxito o error
    """
    # Verificar que el usuario sea un coach
    if role != 2:
        raise HTTPException(
            status_code=403,
            detail="Unauthorized: User is not a coach"
        )
    
    result = unassign_routine_from_client(client_id, routine_id, coach_id)
    
    if not result["success"]:
        if "Unauthorized" in result["message"]:
            raise HTTPException(status_code=403, detail=result["message"])
        elif "not found" in result["message"]:
            raise HTTPException(status_code=404, detail=result["message"])
        else:
            raise HTTPException(status_code=500, detail=result["message"])
            
    return {"message": result["message"]}

@app.post("/users/{client_id}/routines/{routine_id}")
async def assign_routine(
    client_id: int,
    routine_id: int,
    coach_id: int = Depends(auth_user_id),
    role: int = Depends(auth_user_role)
):
    """
    Endpoint para asignar una rutina a un cliente.
    Solo puede ser ejecutado por un coach y debe ser dueño de la rutina.
    
    Args:
        client_id (int): ID del cliente
        routine_id (int): ID de la rutina a asignar
        
    Returns:
        dict: Mensaje de éxito o error
    """
    # Verificar que el usuario sea un coach
    if role != 2:
        raise HTTPException(
            status_code=403,
            detail="Unauthorized: User is not a coach"
        )
    
    result = assign_routine_to_client(client_id, routine_id, coach_id)
    
    if not result["success"]:
        if "Unauthorized" in result["message"]:
            raise HTTPException(status_code=403, detail=result["message"])
        elif "already assigned" in result["message"]:
            raise HTTPException(status_code=400, detail=result["message"])
        else:
            raise HTTPException(status_code=500, detail=result["message"])
            
    return {"message": result["message"]}

@app.get("/clients/unassigned")
async def get_unassigned_clients_endpoint(
    token: str = Depends(oauth2),
    role: int = Depends(auth_user_role)
):
    """
    Endpoint para obtener todos los usuarios con rol de cliente que no tienen coach asignado.
    Requiere autenticación y rol de coach o admin.
    
    Returns:
        list: Lista de clientes sin coach asignado
    """
    # Verificar que el usuario sea coach o admin (roles 2 o 3)
    if role < 2:
        raise HTTPException(
            status_code=403,
            detail="Unauthorized: Insufficient permissions"
        )
    
    try:
        # Llamada a la función síncrona
        clients = get_unassigned_clients()
        return clients
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail="Error retrieving unassigned clients"
        )

@app.post("/workouts")
async def create_workout_endpoint(
    workout_data: dict,
    current_user_id: int = Depends(auth_user_id)
):
    """
    Endpoint para crear un nuevo workout con sus ejercicios y sets.
    Requiere autenticación.
    
    Args:
        workout_data (dict): Datos del workout y sus ejercicios
        
    Returns:
        dict: Resultado de la operación
    """
    try:
        # Asegurar que el user_id en los datos coincida con el usuario autenticado
        workout_data["workout"]["user_id"] = current_user_id
        
        result = create_workout(workout_data)
        
        if not result["success"]:
            raise HTTPException(
                status_code=500,
                detail=result["message"]
            )
            
        return {"message": "Workout created successfully", "workout_id": result["workout_id"]}
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error creating workout: {str(e)}"
        )

@app.get("/workouts/volume/{user_id}")
async def get_workouts_volume(
    user_id: int,
    period: str,  # 'week', 'month', 'year'
    response: Response = None
):
    """
    Endpoint para obtener el volumen total de entrenamiento para diferentes períodos.
    Requiere el ID del usuario como parámetro.
    
    Args:
        user_id (int): ID del usuario para el cual se obtendrá el volumen de entrenamiento.
        period (str): Período de tiempo para las estadísticas ('week', 'month', 'year')
    
    Returns:
        list: Lista de volúmenes de entrenamiento con su fecha
    """
    try:
        # Agregar headers para evitar caché
        if response:
            response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
        
        if period == 'week':
            data = get_workouts_volume_by_week(user_id)
        elif period == 'month':
            data = get_workouts_volume_by_month(user_id)
        elif period == 'year':
            data = get_workouts_volume_by_year(user_id)
        else:
            raise HTTPException(
                status_code=400,
                detail="Invalid period. Must be 'week', 'month', or 'year'"
            )
        
        # Imprimir el JSON que se enviará
        print("\nJSON enviado:")
        print(json.dumps(data, indent=2))
        
        return data
        
    except Exception as e:
        print(f"Error en endpoint: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Error retrieving workouts volume: {str(e)}"
        )

@app.get("/workouts/volume/muscle-groups/{user_id}")
async def get_workouts_volume_by_muscle(
    user_id: int,
    period: str,  # 'week', 'month', 'year'
    response: Response = None
):
    """
    Endpoint para obtener el volumen de entrenamiento por grupo muscular para diferentes períodos.
    Requiere el ID del usuario como parámetro.
    
    Args:
        user_id (int): ID del usuario para el cual se obtendrá el volumen de entrenamiento.
        period (str): Período de tiempo para las estadísticas ('week', 'month', 'year')
    
    Returns:
        list: Lista de volúmenes de entrenamiento por grupo muscular con su fecha
    """
    try:
        # Agregar headers para evitar caché
        if response:
            response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
        
        if period == 'week':
            data = get_volume_by_muscle_group_week(user_id)
        elif period == 'month':
            data = get_volume_by_muscle_group_month(user_id)
        elif period == 'year':
            data = get_volume_by_muscle_group_year(user_id)
        else:
            raise HTTPException(
                status_code=400,
                detail="Invalid period. Must be 'week', 'month', or 'year'"
            )
        
        if data is None:
            raise HTTPException(
                status_code=500,
                detail="Error retrieving muscle group volumes"
            )
        
        # Imprimir el JSON que se enviará
        print("\nJSON enviado:")
        print(json.dumps(data, indent=2))
        
        return data
        
    except Exception as e:
        print(f"Error en endpoint: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Error retrieving muscle group volumes: {str(e)}"
        )

@app.get("/workouts/sets/muscle-groups/{user_id}")
async def get_workouts_sets_by_muscle(
    user_id: int,
    period: str,  # 'week', 'month', 'year'
    response: Response = None
):
    """
    Endpoint para obtener el número de series por grupo muscular para diferentes períodos.
    Requiere el ID del usuario como parámetro.
    
    Args:
        user_id (int): ID del usuario para el cual se obtendrán las series.
        period (str): Período de tiempo para las estadísticas ('week', 'month', 'year')
    
    Returns:
        list: Lista de series por grupo muscular con su fecha
    """
    try:
        # Agregar headers para evitar caché
        if response:
            response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
        
        if period == 'week':
            data = get_sets_by_muscle_group_week(user_id)
        elif period == 'month':
            data = get_sets_by_muscle_group_month(user_id)
        elif period == 'year':
            data = get_sets_by_muscle_group_year(user_id)
        else:
            raise HTTPException(
                status_code=400,
                detail="Invalid period. Must be 'week', 'month', or 'year'"
            )
        
        if data is None:
            raise HTTPException(
                status_code=500,
                detail="Error retrieving muscle group sets"
            )
        
        # Imprimir el JSON que se enviará
        print("\nJSON enviado:")
        print(json.dumps(data, indent=2))
        
        return data
        
    except Exception as e:
        print(f"Error en endpoint: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Error retrieving muscle group sets: {str(e)}"
        )

@app.get("/user/weights")
async def get_user_weights_endpoint(
    user_id: int,
    period: str = "week"
):
    """
    Endpoint para obtener los registros de peso del usuario.
    Permite seleccionar entre semana, mes y año.
    """
    try:
        if period == "week":
            data = get_user_weights_week(user_id)
        elif period == "month":
            data = get_user_weights_month(user_id)
        elif period == "year":
            data = get_user_monthly_weight_average(user_id)
        else:
            raise HTTPException(
                status_code=400,
                detail="Invalid period specified. Choose 'week', 'month', or 'year'."
            )
        
        if data is None:
            raise HTTPException(
                status_code=500,
                detail="Error retrieving user weights"
            )
        return data
    except Exception as e:
        print(f"Error en endpoint: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Error retrieving user weights: {str(e)}"
        )

@app.get("/coaches")
async def get_coaches_endpoint():
    """
    Endpoint para obtener todos los coaches registrados.
    
    Returns:
        list: Lista de coaches con su id, nombre e imagen
    """
    try:
        coaches = get_coaches()
        return coaches
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail="Error retrieving coaches"
        )



@app.put("/users/{user_id}/promote-to-coach")
async def promote_to_coach(
    user_id: int,
    current_role: int = Depends(auth_user_role)
):
    """
    Endpoint para promover un usuario de cliente a coach.
    Solo puede ser ejecutado por administradores.
    
    Args:
        user_id (int): ID del usuario a promover
        
    Returns:
        dict: Mensaje de éxito o error
    """
    # Verificar que el usuario sea administrador
    if current_role != 3:
        raise HTTPException(
            status_code=403,
            detail="Unauthorized: Only administrators can promote users to coach"
        )
    
    result = update_user_to_coach(user_id)
    
    if not result["success"]:
        raise HTTPException(
            status_code=400,
            detail=result["message"]
        )
        
    return {"message": result["message"]}

@app.get("/users/{user_id}/details")
async def get_user_details_endpoint(user_id: int):
    """
    Endpoint para obtener detalles de un usuario.
    Devuelve diferentes datos según el rol del usuario.
    
    Returns:
        Para coaches:
        {
            "id": int,
            "name": str,
            "bio": str,
            "image_url": str,
            "role": "coach",
            "client_count": int
        }
        
        Para clientes:
        {
            "id": int,
            "name": str,
            "bio": str,
            "image_url": str,
            "role": "client",
            "workout_count": int,
            "membership_days_remaining": int
        }
    """
    try:
        user_details = get_user_details(user_id)
        
        if user_details is None:
            raise HTTPException(
                status_code=404,
                detail="User not found"
            )
        
        print("\n=== DEBUG - JSON Response ===")
        print(json.dumps(user_details, indent=2))
        print("===========================\n")
            
        return user_details
        
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error retrieving user details: {str(e)}"
        )

@app.put("/users/{user_id}/demote-to-client")
async def demote_to_client(
    user_id: int,
    current_role: int = Depends(auth_user_role)
):
    """
    Endpoint para degradar un coach a cliente.
    Solo puede ser ejecutado por administradores.
    
    Args:
        user_id (int): ID del usuario a degradar
        
    Returns:
        dict: Mensaje de éxito o error
    """
    # Verificar que el usuario sea administrador
    if current_role != 3:
        raise HTTPException(
            status_code=403,
            detail="Unauthorized: Only administrators can demote coaches"
        )
    
    result = demote_coach_to_client(user_id)
    
    if not result["success"]:
        raise HTTPException(
            status_code=400,
            detail=result["message"]
        )
        
    return {"message": result["message"]}

@app.get("/coaches/{coach_id}/routines")
async def get_coach_routines_endpoint(
    coach_id: int,
    current_role: int = Depends(auth_user_role)
):
    """
    Endpoint para obtener las rutinas de un coach específico.
    Solo puede ser accedido por administradores.
    
    Args:
        coach_id (int): ID del coach
        
    Returns:
        list: Lista de rutinas con formato:
        [
            {
                "id": int,
                "name": str,
                "description": str,
                "created_at": str (ISO date),
                "assigned_clients_count": int
            },
            ...
        ]
    """
    # Verificar que el usuario sea administrador
    if current_role != 3:
        raise HTTPException(
            status_code=403,
            detail="Unauthorized: Only administrators can access this endpoint"
        )
    
    routines = get_coach_routines_by_id(coach_id)
    
    if routines is None:
        raise HTTPException(
            status_code=404,
            detail="Coach not found or user is not a coach"
        )
        
    return routines


@app.delete("/admin/routines/{routine_id}")
async def delete_routine_admin(
    routine_id: int,
    current_role: int = Depends(auth_user_role)
):
    """
    Endpoint para que un administrador elimine una rutina y todos sus datos asociados.
    
    Args:
        routine_id (int): ID de la rutina a eliminar
        
    Returns:
        dict: Mensaje de éxito o error
    """
    # Verificar que el usuario sea administrador
    if current_role != 3:
        raise HTTPException(
            status_code=403,
            detail="Unauthorized: Only administrators can use this endpoint"
        )
    
    result = delete_routine_by_admin(routine_id)
    
    if not result["success"]:
        if "not found" in result["message"]:
            raise HTTPException(status_code=404, detail=result["message"])
        else:
            raise HTTPException(status_code=500, detail=result["message"])
            
    return {"message": result["message"]}

@app.get("/memberships")
async def get_memberships():
    """
    Endpoint para obtener todas las membresías.
    
    Returns:
        list: Lista de membresías con formato:
        [
            {
                "id": int,
                "membership_name": str,
                "price": float,
                "days": int,
                "active": bool
            },
            ...
        ]
    """
    try:
        memberships = get_active_memberships()
        
        if memberships is None:
            raise HTTPException(
                status_code=500,
                detail="Error retrieving memberships"
            )
            
        return memberships
        
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error: {str(e)}"
        )

@app.get("/memberships/{membership_id}")
async def get_membership(membership_id: int):
    """
    Endpoint para obtener los detalles de una membresía específica.
    
    Args:
        membership_id (int): ID de la membresía
        
    Returns:
        dict: Detalles de la membresía
    """
    try:
        membership = get_membership_by_id(membership_id)
        
        if membership is None:
            raise HTTPException(
                status_code=404,
                detail="Membership not found"
            )
            
        return membership
        
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error: {str(e)}"
        )

class MembershipUpdate(BaseModel):
    membership_name: str
    price: float
    days: int
    active: bool

@app.put("/memberships/{membership_id}")
async def update_membership_endpoint(
    membership_id: int,
    membership: MembershipUpdate,
    current_role: int = Depends(auth_user_role)
):
    """
    Endpoint para actualizar una membresía.
    Solo puede ser usado por administradores.
    
    Args:
        membership_id (int): ID de la membresía a actualizar
        membership (MembershipUpdate): Datos nuevos de la membresía
        
    Returns:
        dict: Mensaje de éxito o error
    """
    # Verificar que el usuario sea administrador
    if current_role != 3:
        raise HTTPException(
            status_code=403,
            detail="Unauthorized: Only administrators can update memberships"
        )
    
    result = update_membership(membership_id, membership.dict())
    
    if not result["success"]:
        if "not found" in result["message"]:
            raise HTTPException(status_code=404, detail=result["message"])
        else:
            raise HTTPException(status_code=500, detail=result["message"])
            
    return {"message": result["message"]}


@app.post("/memberships")
async def create_membership_endpoint(
    membership_data: dict,
    current_role: int = Depends(auth_user_role)
):
    """
    Endpoint para crear una nueva membresía.
    Solo puede ser usado por administradores.
    
    Returns:
        dict: Mensaje de éxito o error con el ID de la membresía creada
    """
    # Verificar que el usuario sea administrador
    if current_role != 3:
        raise HTTPException(
            status_code=403,
            detail="Unauthorized: Only administrators can create memberships"
        )
    
    result = create_membership(membership_data)
    
    if not result["success"]:
        raise HTTPException(
            status_code=500,
            detail=result["message"]
        )
            
    return {
        "message": result["message"],
        "membership_id": result["id"]
    }

class PaymentRequest(BaseModel):
    payment_method: int

@app.post("/users/{user_id}/memberships/{membership_id}")
async def register_membership_payment_endpoint(
    user_id: int,
    membership_id: int,
    payment_data: PaymentRequest,
    current_role: int = Depends(auth_user_role)
):
    """
    Endpoint para registrar un nuevo pago de membresía.
    Solo puede ser ejecutado por administradores.
    
    Args:
        user_id (int): ID del usuario
        membership_id (int): ID de la membresía
        payment_data: JSON con el método de pago
        
    Returns:
        dict: Mensaje de éxito o error
    """
    # Verificar que el usuario sea administrador
    if current_role != 3:
        raise HTTPException(
            status_code=403,
            detail="No autorizado: Solo los administradores pueden registrar pagos"
        )
    
    result = register_membership_payment(user_id, membership_id, payment_data.payment_method)
    
    if not result["success"]:
        raise HTTPException(
            status_code=400,
            detail=result["message"]
        )
            
    return {"message": result["message"]}

@app.delete("/users/{user_id}/memberships/revoke")
async def revoke_membership_endpoint(
    user_id: int,
    current_role: int = Depends(auth_user_role)
):
    """
    Endpoint para revocar la membresía activa de un usuario.
    Solo puede ser ejecutado por administradores.
    La membresía se marca como expirada pero se mantiene el registro.
    
    Args:
        user_id (int): ID del usuario
        
    Returns:
        dict: Mensaje de éxito o error
    """
    # Verificar que el usuario sea administrador
    if current_role != 3:
        raise HTTPException(
            status_code=403,
            detail="No autorizado: Solo los administradores pueden revocar membresías"
        )
    
    try:
        result = revoke_user_membership(user_id)
        
        if not result["success"]:
            raise HTTPException(
                status_code=400,
                detail=result["message"]
            )
                
        return {"message": result["message"]}
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )

@app.get("/memberships/payments/stats")
async def get_membership_payment_stats(
    period: str,  # 'week', 'month', 'year'
    current_role: int = Depends(auth_user_role)
):
    """
    Obtiene estadísticas de pagos de membresías en efectivo (método 1) para diferentes períodos.
    
    Args:
        period (str): Período de tiempo para las estadísticas ('week', 'month', 'year')
    """
    if current_role != 3:
        raise HTTPException(
            status_code=403,
            detail="Unauthorized: Only administrators can access payment statistics"
        )
        
    try:
        if period == 'week':
            data = get_membership_stats_by_week()
        elif period == 'month':
            data = get_membership_stats_by_month()
        elif period == 'year':
            data = get_membership_stats_by_year()
        else:
            raise HTTPException(
                status_code=400,
                detail="Invalid period. Must be 'week', 'month', or 'year'"
            )
            
        # Imprimir el JSON que se enviará
        print("\nJSON enviado:")
        print(json.dumps(data, indent=2))
            
        return data
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error retrieving payment statistics: {str(e)}"
        )

@app.get("/memberships/online-payments/stats")
async def get_online_membership_payment_stats(
    period: str,  # 'week', 'month', 'year'
    current_role: int = Depends(auth_user_role)
):
    """
    Obtiene estadísticas de pagos de membresías en línea (método 2) para diferentes períodos.
    
    Args:
        period (str): Período de tiempo para las estadísticas ('week', 'month', 'year')
    """
    if current_role != 3:
        raise HTTPException(
            status_code=403,
            detail="Unauthorized: Only administrators can access payment statistics"
        )
        
    try:
        if period == 'week':
            data = get_online_membership_stats_by_week()
        elif period == 'month':
            data = get_online_membership_stats_by_month()
        elif period == 'year':
            data = get_online_membership_stats_by_year()
        else:
            raise HTTPException(
                status_code=400,
                detail="Invalid period. Must be 'week', 'month', or 'year'"
            )
            
        # Imprimir el JSON que se enviará
        print("\nJSON enviado:")
        print(json.dumps(data, indent=2))
            
        return data
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error retrieving online payment statistics: {str(e)}"
        )

@app.get("/memberships/all-payments/stats")
async def get_all_membership_payment_stats(
    period: str,  # 'week', 'month', 'year'
    current_role: int = Depends(auth_user_role)
):
    """
    Obtiene estadísticas de todos los pagos de membresías (efectivo y online) para diferentes períodos.
    
    Args:
        period (str): Período de tiempo para las estadísticas ('week', 'month', 'year')
    """
    if current_role != 3:
        raise HTTPException(
            status_code=403,
            detail="Unauthorized: Only administrators can access payment statistics"
        )
        
    try:
        if period == 'week':
            data = get_all_membership_stats_by_week()
        elif period == 'month':
            data = get_all_membership_stats_by_month()
        elif period == 'year':
            data = get_all_membership_stats_by_year()
        else:
            raise HTTPException(
                status_code=400,
                detail="Invalid period. Must be 'week', 'month', or 'year'"
            )
            
        # Imprimir el JSON que se enviará
        print("\nJSON enviado:")
        print(json.dumps(data, indent=2))
            
        return data
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error retrieving payment statistics: {str(e)}"
        )

@app.get("/workouts/{workout_id}")
async def get_workout_detail_endpoint(
    workout_id: int,
    token: str = Depends(oauth2),
    current_user_id: int = Depends(auth_user_id),
    current_role: int = Depends(auth_user_role)
):
    """
    Endpoint para obtener información detallada de un workout específico.
    Requiere autenticación y verifica que el usuario tenga acceso al workout.
    
    Args:
        workout_id (int): ID del workout a consultar
        
    Returns:
        dict: Información detallada del workout con sus ejercicios y sets
    """
    try:
        workout = get_workout_detail(workout_id)
        
        if workout is None:
            raise HTTPException(
                status_code=404,
                detail="Workout not found"
            )
            
        # Verificar que el usuario tenga acceso al workout
        # Los coaches y admins pueden ver todos los workouts
        if current_role == 1:  # Si es cliente
            # Verificar que el workout pertenezca al usuario
            connection = obtener_conexion()
            cursor = connection.cursor(dictionary=True)
            
            query = "SELECT user_id FROM workouts WHERE id = %s"
            cursor.execute(query, (workout_id,))
            result = cursor.fetchone()
            
            if result['user_id'] != current_user_id:
                raise HTTPException(
                    status_code=403,
                    detail="No tienes permiso para ver este workout"
                )
                
        return workout
        
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error retrieving workout details: {str(e)}"
        )
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()

@app.get("/users/{user_id}/workouts")
async def get_user_workouts_endpoint(
    user_id: int,
    token: str = Depends(oauth2),
    current_user_id: int = Depends(auth_user_id),
    current_role: int = Depends(auth_user_role)
):
    """
    Endpoint para obtener la lista de workouts de un usuario.
    Requiere autenticación y verifica permisos.
    
    Args:
        user_id (int): ID del usuario del cual se quieren obtener los workouts
        
    Returns:
        list: Lista de workouts con información básica
    """
    try:
        # Verificar permisos
        if current_role == 1 and current_user_id != user_id:  # Si es cliente
            raise HTTPException(
                status_code=403,
                detail="No tienes permiso para ver los workouts de otro usuario"
            )
            
        workouts = get_user_workouts(user_id)
        
        if workouts is None:
            raise HTTPException(
                status_code=500,
                detail="Error retrieving workouts"
            )
            
        return workouts
        
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error retrieving workouts: {str(e)}"
        )

@app.get("/api/clients/{client_id}/name")
async def get_client_name(client_id: int, token: str = Depends(oauth2)):
    """
    Endpoint para obtener el nombre de un cliente específico.
    
    Args:
        client_id (int): ID del cliente
        
    Returns:
        dict: Nombre del cliente
    """
    try:
        user_details = get_user_details(client_id)
        
        if user_details is None:
            raise HTTPException(
                status_code=404,
                detail="User not found"
            )
        
        return {"name": user_details["name"]}
        
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error retrieving client name: {str(e)}"
        )


@app.put("/users/{user_id}/profile")
async def update_user_profile(
    user_id: int,
    name: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    image: Optional[UploadFile] = File(None),
    current_user_id: int = Depends(auth_user_id)
):
    """
    Endpoint para actualizar el perfil de un usuario, incluyendo la foto de perfil.
    
    Args:
        user_id (int): ID del usuario a actualizar.
        name (Optional[str]): Nuevo nombre del usuario.
        description (Optional[str]): Nueva descripción del usuario.
        image (Optional[UploadFile]): Nueva imagen de perfil.
        
    Returns:
        dict: Mensaje de éxito o error.
    """
    if user_id != current_user_id:
        raise HTTPException(
            status_code=403,
            detail="No tienes permiso para editar este perfil"
        )
    
    try:
        db_image_path = None
        if image:
            # Genera un nombre único para el archivo de imagen
            file_extension = os.path.splitext(image.filename)[1]
            unique_filename = f"profile_{user_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}{file_extension}"

            # Guarda el archivo en la carpeta especificada
            file_path = os.path.join(UPLOAD_FOLDER2, unique_filename)
            with open(file_path, "wb") as buffer:
                shutil.copyfileobj(image.file, buffer)

            # La ruta que se guardará en la base de datos
            db_image_path = f"http://127.0.0.1:8000/profileImages/{unique_filename}"

        # Actualizar el perfil en la base de datos
        success = update_user_profile_in_db(user_id, name, description, db_image_path)
        
        if not success:
            if image:
                # Si falla la actualización en la BD, elimina la imagen guardada
                os.remove(file_path)
            raise HTTPException(
                status_code=500,
                detail="Error al actualizar el perfil del usuario"
            )
        
        return {"message": "Perfil actualizado exitosamente"}
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error al actualizar el perfil: {str(e)}"
        )

@app.post("/users/{user_id}/weight")
async def register_user_weight(
    user_id: int,
    weight: float = Form(...),
    current_user_id: int = Depends(auth_user_id)
):
    """
    Endpoint para registrar el peso de un usuario.
    
    Args:
        user_id (int): ID del usuario.
        weight (float): Peso del usuario.
        
    Returns:
        dict: Mensaje de éxito o error.
    """
    if user_id != current_user_id:
        raise HTTPException(
            status_code=403,
            detail="No tienes permiso para registrar el peso de este usuario"
        )
    
    try:
        # Registrar el peso en la base de datos con la fecha de hoy
        success = register_user_weight_in_db(user_id, weight, date.today())
        
        if not success:
            raise HTTPException(
                status_code=500,
                detail="Error al registrar el peso del usuario"
            )
        
        return {"message": "Peso registrado exitosamente"}
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error al registrar el peso: {str(e)}"
        )

@app.post("/create-recipe/")
async def create_recipe(
    name: str = Form(...),
    description: str = Form(...),
    image: UploadFile = File(...),
    user_id: int = Depends(auth_user_id),
    role: int = Depends(auth_user_role)
):
    if role not in [2, 3]:  # Verifica que el usuario sea un coach o admin
        raise HTTPException(status_code=403, detail="Unauthorized")

    try:
        # Genera un nombre único para el archivo
        file_extension = os.path.splitext(image.filename)[1]
        unique_filename = f"recipe_{datetime.now().strftime('%Y%m%d_%H%M%S')}{file_extension}"

        # Guarda el archivo en la carpeta especificada
        file_path = os.path.join(UPLOAD_FOLDER_RECIPES, unique_filename)
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(image.file, buffer)

        # La ruta que se guardará en la base de datos
        db_image_path = f"http://127.0.0.1:8000/recipeImages/{unique_filename}"

        # Guarda la receta en la base de datos con la ruta de la imagen
        if add_recipe(name, description, db_image_path):
            return {"message": "Recipe created successfully"}
        else:
            # Si falla la inserción en la BD, elimina la imagen guardada
            os.remove(file_path)
            raise HTTPException(status_code=400, detail="An error occurred while creating the recipe")

    except Exception as e:
        # Manejo de errores
        print(f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.delete("/recipes/{recipe_id}")
async def delete_recipe(
    recipe_id: int,
    user_id: int = Depends(auth_user_id),
    role: int = Depends(auth_user_role)
):
    """
    Endpoint para eliminar una receta.
    
    Args:
        recipe_id (int): ID de la receta a eliminar.
        
    Returns:
        dict: Mensaje de éxito o error.
    """
    if role not in [2, 3]:  # Verifica que el usuario sea un coach o admin
        raise HTTPException(status_code=403, detail="Unauthorized")

    try:
        # Eliminar la receta de la base de datos
        success = delete_recipe_from_db(recipe_id)
        
        if not success:
            raise HTTPException(
                status_code=404,
                detail="Recipe not found"
            )
        
        return {"message": "Recipe deleted successfully"}
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error deleting recipe: {str(e)}"
        )

@app.put("/recipes/{recipe_id}")
async def update_recipe(
    recipe_id: int,
    name: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    image: Optional[UploadFile] = File(None),
    user_id: int = Depends(auth_user_id),
    role: int = Depends(auth_user_role)
):
    """
    Endpoint para actualizar una receta.
    
    Args:
        recipe_id (int): ID de la receta a actualizar.
        name (Optional[str]): Nuevo nombre de la receta.
        description (Optional[str]): Nueva descripción de la receta.
        image (Optional[UploadFile]): Nueva imagen de la receta.
        
    Returns:
        dict: Mensaje de éxito o error.
    """
    if role not in [2, 3]:  # Verifica que el usuario sea un coach o admin
        raise HTTPException(status_code=403, detail="Unauthorized")

    try:
        db_image_path = None
        if image:
            # Genera un nombre único para el archivo de imagen
            file_extension = os.path.splitext(image.filename)[1]
            unique_filename = f"recipe_{datetime.now().strftime('%Y%m%d_%H%M%S')}{file_extension}"

            # Guarda el archivo en la carpeta especificada
            file_path = os.path.join(UPLOAD_FOLDER_RECIPES, unique_filename)
            with open(file_path, "wb") as buffer:
                shutil.copyfileobj(image.file, buffer)

            # La ruta que se guardará en la base de datos
            db_image_path = f"http://127.0.0.1:8000/recipeImages/{unique_filename}"

        # Actualizar la receta en la base de datos
        success = update_recipe_in_db(recipe_id, name, description, db_image_path)
        
        if not success:
            if image:
                # Si falla la actualización en la BD, elimina la imagen guardada
                os.remove(file_path)
            raise HTTPException(
                status_code=500,
                detail="Error al actualizar la receta"
            )
        
        return {"message": "Recipe updated successfully"}
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error al actualizar la receta: {str(e)}"
        )

@app.get("/recipes/{recipe_id}")
async def get_recipe(
    recipe_id: int,
    user_id: int = Depends(auth_user_id),
    role: int = Depends(auth_user_role)
):
    """
    Endpoint para obtener una receta por su ID.
    
    Args:
        recipe_id (int): ID de la receta a obtener.
        
    Returns:
        dict: Detalles de la receta.
    """
    try:
        recipe = get_recipe_from_db(recipe_id)
        
        if recipe is None:
            raise HTTPException(
                status_code=404,
                detail="Recipe not found"
            )
        
        return recipe
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error retrieving recipe: {str(e)}"
        )

@app.get("/recipes/")
async def get_all_recipes(
    user_id: int = Depends(auth_user_id),
    role: int = Depends(auth_user_role)
):
    """
    Endpoint para obtener el nombre y el ID de todas las recetas.
    
    Returns:
        list: Lista de recetas con sus nombres e IDs.
    """
    try:
        recipes = get_all_recipes_from_db()
        
        if recipes is None:
            raise HTTPException(
                status_code=404,
                detail="No recipes found"
            )
        
        return recipes
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error retrieving recipes: {str(e)}"
        )

@app.get("/exercises/{exercise_id}")
async def get_exercise(exercise_id: int):
    """
    Endpoint para obtener la información de un ejercicio por su ID.
    
    Args:
        exercise_id (int): ID del ejercicio a obtener.
        
    Returns:
        dict: Detalles del ejercicio.
    """
    try:
        exercise = get_exercise_by_id(exercise_id)
        
        if exercise is None:
            raise HTTPException(
                status_code=404,
                detail="Exercise not found"
            )
        
        return exercise
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error retrieving exercise: {str(e)}"
        )

@app.put("/exercises/{exercise_id}")
async def update_exercise(
    exercise_id: int,
    name: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    muscle_group_id: Optional[int] = Form(None),
    image: Optional[UploadFile] = File(None),
    coach_id: int = Depends(auth_user_id),
    role: int = Depends(auth_user_role)
):
    """
    Endpoint para actualizar un ejercicio.

    Args:
        exercise_id (int): ID del ejercicio a actualizar.
        name (Optional[str]): Nuevo nombre del ejercicio.
        description (Optional[str]): Nueva descripción del ejercicio.
        muscle_group_id (Optional[int]): Nuevo ID del grupo muscular.
        image (Optional[UploadFile]): Nueva imagen del ejercicio.
        
    Returns:
        dict: Mensaje de éxito o error.
    """
    if role != 2:  # Verifica que el usuario sea un coach
        raise HTTPException(status_code=403, detail="Unauthorized")

    image_url = None
    if image:
        # Genera un nombre único para el archivo
        file_extension = os.path.splitext(image.filename)[1]
        unique_filename = f"exercise_{datetime.now().strftime('%Y%m%d_%H%M%S')}{file_extension}"

        # Guarda el archivo en la carpeta especificada
        file_path = os.path.join(UPLOAD_FOLDER, unique_filename)
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(image.file, buffer)

        # La ruta que se guardará en la base de datos
        image_url = f"http://127.0.0.1:8000/exerciseImg/{unique_filename}"

    try:
        if update_exercise_in_db(exercise_id, name, description, muscle_group_id, image_url):
            return {"message": "Exercise updated successfully"}
        else:
            raise HTTPException(status_code=400, detail="An error occurred while updating the exercise")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.delete("/exercises/{exercise_id}")
async def delete_exercise(
    exercise_id: int,
    coach_id: int = Depends(auth_user_id),
    role: int = Depends(auth_user_role)
):
    """
    Endpoint para eliminar un ejercicio.

    Args:
        exercise_id (int): ID del ejercicio a eliminar.
        
    Returns:
        dict: Mensaje de éxito o error.
    """
    if role != 2:  # Verifica que el usuario sea un coach
        raise HTTPException(status_code=403, detail="Unauthorized")

    try:
        if delete_exercise_from_db(exercise_id):
            return {"message": "Exercise deleted successfully"}
        else:
            raise HTTPException(status_code=404, detail="Exercise not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")