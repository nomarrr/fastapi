import mysql.connector
import json
import bcrypt
from fastapi import HTTPException
from typing import Dict, Any, Optional
from datetime import datetime, timedelta, date
import os


# Función para obtener una nueva conexión
def obtener_conexion():
    return mysql.connector.connect(
        user=os.getenv('DB_USER', 'root'),
        password=os.getenv('DB_PASSWORD', 'DdQoSoPVukDdAXNbrIogKUhARYyixouA'),
        host=os.getenv('DB_HOST', 'monorail.proxy.rlwy.net'),
        database=os.getenv('DB_NAME', 'gym'),
        port=int(os.getenv('DB_PORT', '13401'))
    )


def add_user(name: str, email: str, password: str):
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            if cursor.fetchone():
                return False

            cursor.execute("INSERT INTO users (name, email, password, role) VALUES (%s, %s, %s, 1)",
                           (name, email, password))
            conexion.commit()
            return True
    except Exception as e:
        conexion.rollback()
        print(f"Error al agregar usuario: {str(e)}")
        return False
    finally:
        conexion.close()


def update_passwordDB(id: int, new_password: str):
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("UPDATE users SET password = %s WHERE id = %s", (new_password, id))
            conexion.commit()
            return True
    except Exception as e:
        conexion.rollback()
        print(f"Error al actualizar contraseña: {str(e)}")
        return False
    finally:
        conexion.close()


def get_clients():
    conexion = obtener_conexion()
    try:
        with conexion.cursor(dictionary=True) as cursor:
            cursor.execute("SELECT * FROM users WHERE role = 1")
            results = cursor.fetchall()
            return json.dumps(results, indent=4)
    finally:
        conexion.close()


def delete_client(id: int):
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("DELETE FROM users WHERE id = %s", (id,))
            conexion.commit()
            return cursor.rowcount > 0
    except Exception as e:
        conexion.rollback()
        print(f"Error al eliminar cliente: {str(e)}")
        return False
    finally:
        conexion.close()


def validate_email(email: str):
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            return cursor.fetchone() is not None
    finally:
        conexion.close()


def validate_password(password: str, id):
    conexion = obtener_conexion()
    try:
        with conexion.cursor(dictionary=True) as cursor:
            if isinstance(id, str):
                cursor.execute("SELECT * FROM users WHERE email = %s", (id,))
            else:
                cursor.execute("SELECT * FROM users WHERE id = %s", (id,))

            user = cursor.fetchone()
            if user:
                hashed_password = user['password'].encode('utf-8')
                return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
            return False
    finally:
        conexion.close()


def get_user_id(email: str):
    conexion = obtener_conexion()
    try:
        with conexion.cursor(dictionary=True) as cursor:
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()
            return user['id'] if user else None
    finally:
        conexion.close()


def get_user_role(email: str):
    conexion = obtener_conexion()
    try:
        with conexion.cursor(dictionary=True) as cursor:
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()
            return user['role'] if user else None
    finally:
        conexion.close()


def get_usersDB():
    conexion = obtener_conexion()
    try:
        with conexion.cursor(dictionary=True) as cursor:
            cursor.execute("SELECT id, name, image_url FROM users WHERE role = 1")
            return cursor.fetchall()
    finally:
        conexion.close()


def create_routine(name: str, description: str, coach_id: int):
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("INSERT INTO routines (name, description, coach_id) VALUES (%s, %s, %s)",
                           (name, description, coach_id))
            conexion.commit()
            return True
    except Exception as e:
        conexion.rollback()
        print(f"Error al crear rutina: {str(e)}")
        return False
    finally:
        conexion.close()


def get_user_routines(user_id: int):
    conexion = obtener_conexion()
    try:
        with conexion.cursor(dictionary=True) as cursor:
            query = """
            SELECT ur.routine_id AS id, r.name 
            FROM user_routines ur
            JOIN routines r ON ur.routine_id = r.id
            WHERE ur.user_id = %s;
            """
            cursor.execute(query, (user_id,))
            return cursor.fetchall()
    finally:
        conexion.close()


def get_routine_exercisesDB(routine_id: int):
    # Obtener conexión a la base de datos
    conexion = obtener_conexion()
    cursor = conexion.cursor(dictionary=True)

    # Consulta SQL para obtener los ejercicios de una rutina específica
    query = """
    SELECT 
        e.id AS id,
        e.name AS name,
        e.description AS description,
        e.image_url AS image_url,
        re.sets AS sets,
        re.position AS position
    FROM routine_exercises re
    JOIN exercises e ON re.exercise_id = e.id
    WHERE re.routine_id = %s
    ORDER BY re.position;
    """

    # Ejecutar la consulta con el parámetro de la rutina
    cursor.execute(query, (routine_id,))
    exercises = cursor.fetchall()

    # Cerrar el cursor y la conexión
    cursor.close()
    conexion.close()

    return exercises


def get_muscle_groups():
    # Obtener conexión a la base de datos
    conexion = obtener_conexion()
    cursor = conexion.cursor(dictionary=True)

    # Consulta SQL para obtener los grupos musculares
    query = """
    SELECT 
        id,
        name
    FROM muscle_groups
    ORDER BY name ASC
    """

    # Ejecutar la consulta
    cursor.execute(query)
    muscle_groups = cursor.fetchall()

    # Cerrar el cursor y la conexión
    cursor.close()
    conexion.close()

    # Convertir los resultados a la estructura JSON requerida
    return muscle_groups


def add_exercise(name: str, description: str, muscle_group_id: int, image_url: str = None):
    """
    Agrega un nuevo ejercicio a la base de datos.

    Args:
        name (str): Nombre del ejercicio.
        description (str): Descripción del ejercicio.
        muscle_group_id (int): ID del grupo muscular al que pertenece el ejercicio.
        image_url (str): URL de la imagen del ejercicio (opcional).
    """
    conexion = obtener_conexion()
    cursor = conexion.cursor()

    query = """
    INSERT INTO exercises (name, description, muscle_group_id, image_url)
    VALUES (%s, %s, %s, %s)
    """

    # Ejecutar el query con los parámetros proporcionados
    cursor.execute(query, (name, description, muscle_group_id, image_url))

    # Confirmar los cambios en la base de datos
    conexion.commit()

    # Cerrar el cursor y la conexión
    cursor.close()
    conexion.close()

    return True


def get_exercises_by_muscle_group_id(muscle_group_id: int):
    try:
        # Conexión a la base de datos
        conexion = obtener_conexion()
        cursor = conexion.cursor(dictionary=True)

        # Consulta SQL para obtener los ejercicios por grupo muscular
        query = """
            SELECT id, name, description, muscle_group_id, image_url
            FROM exercises
            WHERE muscle_group_id = %s
        """
        cursor.execute(query, (muscle_group_id,))
        exercises = cursor.fetchall()

        # Devuelve los resultados directamente como lista de diccionarios
        return exercises

    except Exception as e:
        print(f"Error getting exercises: {str(e)}")
        raise HTTPException(status_code=500, detail="An error occurred while retrieving exercises")
    finally:
        # Asegura que la conexión se cierre
        if 'conexion' in locals() and conexion.is_connected():
            cursor.close()
            conexion.close()


def fetch_coach_routines_from_db(coach_id: int):
    """
    Consulta las rutinas asignadas a un coach específico en la base de datos.
    """
    try:
        connection = obtener_conexion()
        with connection.cursor() as cursor:
            query = """
                SELECT id, name, description
                FROM routines
                WHERE coach_id = %s
            """
            cursor.execute(query, (coach_id,))
            routines = cursor.fetchall()

            # Procesar los resultados en una lista de diccionarios
            result = [
                {"id": routine[0], "name": routine[1], "description": routine[2]}
                for routine in routines
            ]
            return result
    except Exception as e:
        print(f"Error al consultar rutinas en la base de datos: {str(e)}")
        raise
    finally:
        if 'connection' in locals() and connection:
            connection.close()


def fetch_routine_ownership_from_db(routine_id: int, coach_id: int) -> bool:
    """
    Consulta en la base de datos si un coach es propietario de una rutina específica.
    """
    try:
        print(f"Validando propiedad: routine_id={routine_id}, coach_id={coach_id}")  # Log de debugging
        connection = obtener_conexion()
        cursor = connection.cursor()
        
        query = """
            SELECT COUNT(*) 
            FROM routines 
            WHERE id = %s AND coach_id = %s
        """
        cursor.execute(query, (routine_id, coach_id))
        result = cursor.fetchone()
        
        is_owner = result[0] > 0
        print(f"Resultado de validación: {is_owner}")  # Log de debugging
        
        return is_owner
        
    except Exception as e:
        print(f"Error al consultar propiedad de la rutina: {str(e)}")  # Log de debugging
        return False
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()



def update_routine_exercises_in_db(routine_id: int, updated_exercises: list, deleted_exercises: list):
    """
    Actualiza y elimina ejercicios asociados a una rutina en la base de datos.
    """
    try:
        connection = obtener_conexion()
        with connection.cursor() as cursor:
            # Eliminar ejercicios
            if deleted_exercises:
                query_delete = """
                    DELETE FROM routine_exercises
                    WHERE routine_id = %s AND exercise_id IN (%s)
                """
                # Convertir la lista de IDs a una cadena separada por comas
                ids_to_delete = ', '.join(map(str, deleted_exercises))
                cursor.execute(query_delete, (routine_id, ids_to_delete))

            # Actualizar ejercicios
            for exercise in updated_exercises:
                query_upsert = """
                    INSERT INTO routine_exercises (routine_id, exercise_id, sets, position)
                    VALUES (%s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE
                    sets = VALUES(sets), position = VALUES(position)
                """
                cursor.execute(
                    query_upsert,
                    (
                        routine_id,
                        exercise["exercise_id"],
                        exercise["sets"],
                        exercise["position"],
                    ),
                )

        connection.commit()
    except Exception as e:
        print(f"Error al actualizar ejercicios en la rutina: {str(e)}")
        raise
    finally:
        if "connection" in locals() and connection:
            connection.close()


def fetch_routine_with_exercises(routine_id: int, coach_id: int):
    """
    Obtiene la rutina junto con sus ejercicios, verificando la propiedad del coach.

    Args:
        routine_id (int): ID de la rutina.
        coach_id (int): ID del coach (usuario autenticado).

    Returns:
        dict: Rutina con ejercicios en formato estructurado, o None si no se encuentra o no pertenece al coach.
    """
    try:
        connection = obtener_conexion()
        cursor = connection.cursor(dictionary=True)

        # Verificar propiedad de la rutina
        ownership_query = """
            SELECT id, name, coach_id
            FROM routines
            WHERE id = %s AND coach_id = %s
        """
        cursor.execute(ownership_query, (routine_id, coach_id))
        routine = cursor.fetchone()

        if not routine:
            return None  # Rutina no encontrada o no pertenece al coach

        # Obtener ejercicios asociados a la rutina
        exercises_query = """
            SELECT 
                e.id AS exercise_id,
                e.name AS exercise_name,
                re.sets AS sets,
                re.position AS position,
                e.image_url AS exercise_image_url
            FROM routine_exercises re
            JOIN exercises e ON re.exercise_id = e.id
            WHERE re.routine_id = %s
            ORDER BY re.position
        """
        cursor.execute(exercises_query, (routine_id,))
        exercises = cursor.fetchall()

        # Estructurar el resultado
        routine_with_exercises = {
            "id": routine["id"],
            "name": routine["name"],
            "coach_id": routine["coach_id"],
            "exercises": [
                {
                    "id": exercise["exercise_id"],
                    "name": exercise["exercise_name"],
                    "sets": exercise["sets"],
                    "position": exercise["position"],
                    "image_url": exercise["exercise_image_url"]
                }
                for exercise in exercises
            ]
        }

        return routine_with_exercises

    except Exception as e:
        print(f"Error al obtener rutina con ejercicios: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        if "connection" in locals() and connection:
            connection.close()


def update_routine(data: dict):
    """
    Actualiza una rutina con su nombre y ejercicios.

    Args:
        data (dict): JSON con los datos de la rutina. Ejemplo:
            {
                "routine_id": 1,
                "name": "Nueva Rutina",
                "exercises": [
                    {
                        "exercise_id": 5,
                        "sets": 3,
                        "position": 1
                    },
                    {
                        "exercise_id": 2,
                        "sets": 1,
                        "position": 2
                    }
                ]
            }
    """
    routine_id = data["routine_id"]
    routine_name = data["name"]
    exercises = data["exercises"]

    # Obtener la conexión antes del bloque de cursor
    connection = obtener_conexion()
    try:
        # Usar el cursor dentro de un bloque with
        with connection.cursor() as cursor:
            # Actualizar el nombre de la rutina
            update_name_query = """
                UPDATE routines
                SET name = %s
                WHERE id = %s
            """
            cursor.execute(update_name_query, (routine_name, routine_id))

            # Eliminar todos los ejercicios de la rutina
            delete_query = "DELETE FROM routine_exercises WHERE routine_id = %s"
            cursor.execute(delete_query, (routine_id,))

            # Insertar los nuevos ejercicios
            insert_query = """
                INSERT INTO routine_exercises (routine_id, exercise_id, sets, position)
                VALUES (%s, %s, %s, %s)
            """
            for exercise in exercises:
                cursor.execute(insert_query, (
                    routine_id,
                    exercise["exercise_id"],
                    exercise["sets"],
                    exercise["position"]
                ))

            # Confirmar los cambios
            connection.commit()
    except Exception as e:
        # Si ocurre un error, hacer rollback
        connection.rollback()
        print(f"Error actualizando la rutina {routine_id}: {e}")
        raise
    finally:
        # Asegurarse de cerrar la conexión
        if connection and connection.is_connected():
            connection.close()


def create_routine_in_db(routine_data: dict, coach_id: int):
    """
    Registra una nueva rutina en la base de datos junto con sus ejercicios asociados.
    """
    try:
        connection = obtener_conexion()
        cursor = connection.cursor()

        # Insertar la rutina
        query_routine = """
        INSERT INTO routines (name, description, coach_id, created_at)
        VALUES (%s, %s, %s, %s)
        """
        cursor.execute(query_routine, (
            routine_data["name"],
            None,  # description
            coach_id,
            datetime.now()
        ))
        
        routine_id = cursor.lastrowid

        # Insertar los ejercicios asociados
        query_exercise = """
        INSERT INTO routine_exercises (routine_id, exercise_id, sets, position)
        VALUES (%s, %s, %s, %s)
        """
        for exercise in routine_data["exercises"]:
            cursor.execute(query_exercise, (
                routine_id,
                exercise["exercise_id"],
                exercise["sets"],
                exercise["position"]
            ))

        connection.commit()
        return {"routine_id": routine_id, "message": "Routine created successfully"}

    except Exception as e:
        if connection:
            connection.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()


def delete_routine_and_exercises(routine_id: int):
    """
    Elimina una rutina, sus ejercicios asociados y sus asignaciones a usuarios.
    
    Args:
        routine_id (int): ID de la rutina a eliminar
        
    Returns:
        bool: True si la eliminación fue exitosa, False si no
    """
    try:
        connection = obtener_conexion()
        cursor = connection.cursor()

        # Primero eliminamos las asignaciones a usuarios
        delete_assignments_query = """
        DELETE FROM user_routines 
        WHERE routine_id = %s
        """
        cursor.execute(delete_assignments_query, (routine_id,))

        # Luego eliminamos los ejercicios asociados
        delete_exercises_query = """
        DELETE FROM routine_exercises 
        WHERE routine_id = %s
        """
        cursor.execute(delete_exercises_query, (routine_id,))

        # Finalmente eliminamos la rutina
        delete_routine_query = """
        DELETE FROM routines 
        WHERE id = %s
        """
        cursor.execute(delete_routine_query, (routine_id,))

        connection.commit()
        return True

    except Exception as e:
        print(f"Error eliminando rutina: {str(e)}")
        if 'connection' in locals():
            connection.rollback()
        return False
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()


def get_coach_clients(coach_id: int):
    """
    Obtiene todos los clientes asignados a un coach específico.
    
    Args:
        coach_id (int): ID del coach
        
    Returns:
        list: Lista de diccionarios con la información de cada cliente
    """
    try:
        connection = obtener_conexion()
        cursor = connection.cursor(dictionary=True)
        
        query = """
        SELECT u.id, u.name, u.image_url
        FROM users u
        JOIN coach_clients cc ON u.id = cc.client_id
        WHERE cc.coach_id = %s
        ORDER BY u.name
        """
        
        cursor.execute(query, (coach_id,))
        clients = cursor.fetchall()
        
        return clients
        
    except Exception as e:
        print(f"Error obteniendo clientes del coach: {str(e)}")
        return []
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()


def get_client_workout_info_by_id(client_id: int, coach_id: int):
    """
    Obtiene la información de un cliente específico e indica si el coach es responsable.
    
    Args:
        client_id (int): ID del cliente a consultar
        coach_id (int): ID del coach autenticado
        
    Returns:
        dict: Información del cliente o None si no existe
    """
    try:
        connection = obtener_conexion()
        cursor = connection.cursor(dictionary=True)
        
        query = """
        SELECT 
            u.id,
            u.name,
            u.bio,
            u.workouts,
            u.image_url,
            CASE 
                WHEN cc.coach_id = %s THEN TRUE 
                ELSE FALSE 
            END as is_responsible
        FROM users u
        LEFT JOIN coach_clients cc ON u.id = cc.client_id AND cc.coach_id = %s
        WHERE u.id = %s AND u.role = 1
        """
        
        cursor.execute(query, (coach_id, coach_id, client_id))
        client = cursor.fetchone()
        
        if client:
            client['is_responsible'] = bool(client['is_responsible'])
        
        return client
        
    except Exception as e:
        print(f"Error obteniendo información del cliente: {str(e)}")
        return None
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()


def assign_coach_to_client(coach_id: int, client_id: int) -> dict:
    """
    Asigna un coach como responsable de un cliente.
    
    Args:
        coach_id (int): ID del coach
        client_id (int): ID del cliente
        
    Returns:
        dict: Mensaje de éxito o error
    """
    try:
        connection = obtener_conexion()
        cursor = connection.cursor(dictionary=True)
        
        # Verificar que el cliente exista y sea role=1
        cursor.execute("SELECT role FROM users WHERE id = %s", (client_id,))
        client = cursor.fetchone()
        
        if not client:
            return {"success": False, "message": "Client not found"}
        if client['role'] != 1:
            return {"success": False, "message": "User is not a client"}
            
        # Verificar si ya existe la relación
        cursor.execute(
            "SELECT * FROM coach_clients WHERE coach_id = %s AND client_id = %s", 
            (coach_id, client_id)
        )
        if cursor.fetchone():
            return {"success": False, "message": "Coach is already responsible for this client"}
            
        # Insertar la nueva relación
        cursor.execute(
            "INSERT INTO coach_clients (coach_id, client_id) VALUES (%s, %s)",
            (coach_id, client_id)
        )
        
        connection.commit()
        return {"success": True, "message": "Coach assigned successfully"}
        
    except Exception as e:
        print(f"Error asignando coach a cliente: {str(e)}")
        return {"success": False, "message": "Database error"}
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()


def unassign_routine_from_client(client_id: int, routine_id: int, coach_id: int):
    """
    Desasigna una rutina de un cliente, verificando que el coach sea responsable.
    
    Args:
        client_id (int): ID del cliente
        routine_id (int): ID de la rutina
        coach_id (int): ID del coach que intenta desasignar
        
    Returns:
        dict: Diccionario con el resultado de la operación
    """
    try:
        connection = obtener_conexion()
        cursor = connection.cursor()
        
        # Verificar que el coach sea responsable del cliente
        query = """
        SELECT COUNT(*) 
        FROM coach_clients 
        WHERE coach_id = %s AND client_id = %s
        """
        cursor.execute(query, (coach_id, client_id))
        is_responsible = cursor.fetchone()[0] > 0
        
        if not is_responsible:
            return {
                "success": False,
                "message": "Unauthorized: You are not responsible for this client"
            }
            
        # Eliminar la asignación de la rutina
        delete_query = """
        DELETE FROM user_routines 
        WHERE user_id = %s AND routine_id = %s
        """
        cursor.execute(delete_query, (client_id, routine_id))
        
        if cursor.rowcount == 0:
            return {
                "success": False,
                "message": "Routine assignment not found"
            }
            
        connection.commit()
        return {
            "success": True,
            "message": "Routine unassigned successfully"
        }
        
    except Exception as e:
        print(f"Error desasignando rutina: {str(e)}")
        return {
            "success": False,
            "message": "Database error"
        }
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()



def assign_routine_to_client(client_id: int, routine_id: int, coach_id: int):
    """
    Asigna una rutina a un cliente, verificando que el coach sea dueño de la rutina.
    
    Args:
        client_id (int): ID del cliente
        routine_id (int): ID de la rutina
        coach_id (int): ID del coach que intenta asignar
        
    Returns:
        dict: Diccionario con el resultado de la operación
    """
    try:
        connection = obtener_conexion()
        cursor = connection.cursor()
        
        # Verificar que el coach sea dueño de la rutina
        query = """
        SELECT COUNT(*) 
        FROM routines 
        WHERE id = %s AND coach_id = %s
        """
        cursor.execute(query, (routine_id, coach_id))
        is_owner = cursor.fetchone()[0] > 0
        
        if not is_owner:
            return {
                "success": False,
                "message": "Unauthorized: You don't own this routine"
            }
            
        # Verificar que la rutina no esté ya asignada al cliente
        check_query = """
        SELECT COUNT(*)
        FROM user_routines
        WHERE user_id = %s AND routine_id = %s
        """
        cursor.execute(check_query, (client_id, routine_id))
        already_assigned = cursor.fetchone()[0] > 0
        
        if already_assigned:
            return {
                "success": False,
                "message": "Routine is already assigned to this client"
            }
            
        # Asignar la rutina al cliente
        insert_query = """
        INSERT INTO user_routines (user_id, routine_id)
        VALUES (%s, %s)
        """
        cursor.execute(insert_query, (client_id, routine_id))
            
        connection.commit()
        return {
            "success": True,
            "message": "Routine assigned successfully"
        }
        
    except Exception as e:
        print(f"Error asignando rutina: {str(e)}")
        return {
            "success": False,
            "message": "Database error"
        }
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()


def get_unassigned_clients():
    """
    Obtiene todos los usuarios con rol 1 (clientes) que no tienen coach asignado.
    
    Returns:
        list: Lista de clientes sin coach asignado
    """
    try:
        connection = obtener_conexion()
        cursor = connection.cursor(dictionary=True)
        
        query = """
        SELECT 
            u.id,
            u.name,
            u.bio,
            u.workouts,
            u.image_url
        FROM users u
        LEFT JOIN coach_clients cc ON u.id = cc.client_id
        WHERE u.role = 1 AND cc.coach_id IS NULL
        ORDER BY u.name
        """
        
        cursor.execute(query)
        clients = cursor.fetchall()
        
        return clients
        
    except Exception as e:
        print(f"Error obteniendo clientes sin asignar: {str(e)}")
        return []
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()



def create_workout(workout_data: dict):
    """
    Crea un nuevo workout con sus ejercicios y sets asociados.
    Usa el nombre de la rutina como nombre del workout.
    
    Args:
        workout_data (dict): Datos del workout y sus ejercicios
        
    Returns:
        dict: Resultado de la operación
    """
    try:
        connection = obtener_conexion()
        cursor = connection.cursor()
        
        # Convertir la fecha ISO a formato MySQL
        workout_date = datetime.fromisoformat(workout_data["workout"]["date"].replace('Z', '+00:00'))
        
        # Insertar el workout usando el nombre de la rutina y agregando el tiempo
        workout_query = """
        INSERT INTO workouts (name, description, user_id, routine_id, date, time)
        SELECT 
            r.name,
            r.description,
            %s,
            r.id,
            %s,
            %s
        FROM routines r
        WHERE r.id = %s
        """
        cursor.execute(workout_query, (
            workout_data["workout"]["user_id"],
            workout_date,
            workout_data["workout"]["duration"],  # Nuevo campo duration
            workout_data["workout"]["routine_id"]
        ))
        workout_id = cursor.lastrowid
        
        # Insertar los ejercicios del workout
        for exercise in workout_data["workout_exercises"]:
            # Insertar workout_exercise
            exercise_query = """
            INSERT INTO workout_exercises (workout_id, exercise_id, sets, position)
            VALUES (%s, %s, %s, %s)
            """
            cursor.execute(exercise_query, (
                workout_id,
                exercise["exercise_id"],
                exercise["sets"],
                exercise["position"]
            ))
            workout_exercise_id = cursor.lastrowid
            
            # Insertar los sets del ejercicio
            for set_number, set_data in enumerate(exercise["sets_data"], 1):
                # Convertir la fecha del set
                set_date = datetime.fromisoformat(set_data["date"].replace('Z', '+00:00'))
                
                set_query = """
                INSERT INTO workout_exercise_sets 
                (workout_exercise_id, weight, reps, set_number, date)
                VALUES (%s, %s, %s, %s, %s)
                """
                cursor.execute(set_query, (
                    workout_exercise_id,
                    set_data["weight"],
                    set_data["reps"],
                    set_number,
                    set_date
                ))
                
                # Insertar en la tabla sets para histórico
                sets_query = """
                INSERT INTO sets 
                (user_id, exercise_id, weight, reps, muscle_group_id, date)
                SELECT %s, %s, %s, %s, 
                    (SELECT muscle_group_id FROM exercises WHERE id = %s),
                    %s
                """
                cursor.execute(sets_query, (
                    workout_data["workout"]["user_id"],
                    exercise["exercise_id"],
                    set_data["weight"],
                    set_data["reps"],
                    exercise["exercise_id"],
                    set_date
                ))
        
        # Incrementar el contador de workouts del usuario
        update_workouts_query = """
        UPDATE users 
        SET workouts = workouts + 1 
        WHERE id = %s
        """
        cursor.execute(update_workouts_query, (workout_data["workout"]["user_id"],))
        
        connection.commit()
        return {"success": True, "workout_id": workout_id}
        
    except Exception as e:
        print(f"Error creando workout: {str(e)}")
        if 'connection' in locals():
            connection.rollback()
        return {"success": False, "message": str(e)}
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()




def get_last_workouts_volume(user_id: int, limit: int = 7):
    """
    Obtiene el volumen total de los últimos workouts de un usuario.
    El volumen se calcula como la suma de (peso × repeticiones) de todos los ejercicios.
    
    Args:
        user_id (int): ID del usuario
        limit (int): Número máximo de workouts a obtener
        
    Returns:
        list: Lista de workouts con su volumen total y fecha
    """
    try:
        connection = obtener_conexion()
        cursor = connection.cursor(dictionary=True)
        
        query = """
        SELECT 
            w.id,
            w.date,
            COALESCE(SUM(wes.weight * wes.reps), 0) as total_volume
        FROM workouts w
        LEFT JOIN workout_exercises we ON w.id = we.workout_id
        LEFT JOIN workout_exercise_sets wes ON we.id = wes.workout_exercise_id
        WHERE w.user_id = %s
        GROUP BY w.id, w.date
        ORDER BY w.date DESC
        LIMIT %s
        """
        
        cursor.execute(query, (user_id, limit))
        workouts = cursor.fetchall()
        
        print(f"Workouts encontrados: {len(workouts)}")
        for w in workouts:
            print(f"Workout {w['id']}: {w['date']} - Volume: {w['total_volume']}")
            
        formatted_workouts = []
        for workout in workouts:
            formatted_workout = {
                'id': workout['id'],
                'date': workout['date'].isoformat(),
                'total_volume': int(workout['total_volume']) if workout['total_volume'] else 0
            }
            formatted_workouts.append(formatted_workout)
            
        return formatted_workouts
        
    except Exception as e:
        print(f"Error obteniendo volumen de workouts: {str(e)}")
        return []
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()



def get_volume_by_muscle_group(user_id: int, limit: int = 7):  # ahora limit es número de workouts
    try:
        connection = obtener_conexion()
        cursor = connection.cursor(dictionary=True)
        
        query = """
        WITH LastWorkouts AS (
            SELECT DISTINCT w.id, w.date
            FROM workouts w
            WHERE w.user_id = %s
            ORDER BY w.date DESC
            LIMIT %s
        )
        SELECT 
            mg.id as muscle_group_id,
            mg.name as muscle_group_name,
            DATE(w.date) as workout_date,
            SUM(wes.weight * wes.reps) as total_volume
        FROM workouts w
        JOIN LastWorkouts lw ON w.id = lw.id
        JOIN workout_exercises we ON w.id = we.workout_id
        JOIN exercises e ON we.exercise_id = e.id
        JOIN muscle_groups mg ON e.muscle_group_id = mg.id
        JOIN workout_exercise_sets wes ON we.id = wes.workout_exercise_id
        GROUP BY mg.id, mg.name, DATE(w.date)
        ORDER BY workout_date DESC, mg.name
        """
        
        cursor.execute(query, (user_id, limit))
        results = cursor.fetchall()
        
        # Organizamos los datos por grupo muscular
        muscle_groups = {}
        dates = set()
        
        for row in results:
            dates.add(row['workout_date'].isoformat())
            if row['muscle_group_name'] not in muscle_groups:
                muscle_groups[row['muscle_group_name']] = {
                    'id': row['muscle_group_id'],
                    'name': row['muscle_group_name'],
                    'data': {}
                }
            muscle_groups[row['muscle_group_name']]['data'][row['workout_date'].isoformat()] = row['total_volume']
        
        # Convertimos a formato para gráfica
        dates = sorted(list(dates), reverse=True)  # Ordenamos las fechas de más reciente a más antigua
        formatted_data = {
            'dates': dates,
            'muscle_groups': []
        }
        
        for muscle_name, muscle_data in muscle_groups.items():
            volume_data = []
            for date in dates:
                volume_data.append(muscle_data['data'].get(date, 0))
            
            formatted_data['muscle_groups'].append({
                'id': muscle_data['id'],
                'name': muscle_name,
                'volumes': volume_data
            })
        
        return formatted_data
        
    except Exception as e:
        print(f"Error obteniendo volumen por grupo muscular: {str(e)}")
        return None
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()



def get_sets_by_muscle_group(user_id: int, limit: int = 7):
    try:
        connection = obtener_conexion()
        cursor = connection.cursor(dictionary=True)
        
        query = """
        WITH LastWorkouts AS (
            SELECT DISTINCT w.id, w.date
            FROM workouts w
            WHERE w.user_id = %s
            ORDER BY w.date DESC
            LIMIT %s
        )
        SELECT 
            mg.id as muscle_group_id,
            mg.name as muscle_group_name,
            DATE(w.date) as workout_date,
            COUNT(wes.set_number) as total_sets
        FROM workouts w
        JOIN LastWorkouts lw ON w.id = lw.id
        JOIN workout_exercises we ON w.id = we.workout_id
        JOIN exercises e ON we.exercise_id = e.id
        JOIN muscle_groups mg ON e.muscle_group_id = mg.id
        JOIN workout_exercise_sets wes ON we.id = wes.workout_exercise_id
        GROUP BY mg.id, mg.name, DATE(w.date)
        ORDER BY workout_date DESC, mg.name
        """
        
        cursor.execute(query, (user_id, limit))
        results = cursor.fetchall()
        
        # Organizamos los datos por grupo muscular
        muscle_groups = {}
        dates = set()
        
        for row in results:
            dates.add(row['workout_date'].isoformat())
            if row['muscle_group_name'] not in muscle_groups:
                muscle_groups[row['muscle_group_name']] = {
                    'id': row['muscle_group_id'],
                    'name': row['muscle_group_name'],
                    'data': {}
                }
            muscle_groups[row['muscle_group_name']]['data'][row['workout_date'].isoformat()] = row['total_sets']
        
        # Convertimos a formato para gráfica
        dates = sorted(list(dates), reverse=True)
        formatted_data = {
            'dates': dates,
            'muscle_groups': []
        }
        
        for muscle_name, muscle_data in muscle_groups.items():
            sets_data = []
            for date in dates:
                sets_data.append(muscle_data['data'].get(date, 0))
            
            formatted_data['muscle_groups'].append({
                'id': muscle_data['id'],
                'name': muscle_name,
                'sets': sets_data  # Cambiado de 'volumes' a 'sets'
            })
        
        return formatted_data
        
    except Exception as e:
        print(f"Error obteniendo sets por grupo muscular: {str(e)}")
        return None
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()



def get_user_weights(user_id: int):
    try:
        connection = obtener_conexion()
        cursor = connection.cursor(dictionary=True)
        
        query = """
        SELECT date, weight
        FROM user_weight
        WHERE user_id = %s
        ORDER BY date DESC
        """
        
        cursor.execute(query, (user_id,))
        results = cursor.fetchall()
        
        # Formatear los datos para la gráfica
        formatted_data = {
            'dates': [row['date'].isoformat() for row in results],
            'weights': [row['weight'] for row in results]
        }
        
        return formatted_data
        
    except Exception as e:
        print(f"Error obteniendo registros de peso: {str(e)}")
        return None
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()



def get_coaches():
    """
    Obtiene todos los usuarios con rol de coach (role = 2).
    
    Returns:
        list: Lista de coaches con su id, nombre e imagen
    """
    try:
        connection = obtener_conexion()
        cursor = connection.cursor(dictionary=True)
        
        query = """
        SELECT id, name, image_url
        FROM users
        WHERE role = 2
        ORDER BY name
        """
        
        cursor.execute(query)
        coaches = cursor.fetchall()
        
        return coaches
        
    except Exception as e:
        print(f"Error obteniendo coaches: {str(e)}")
        return []
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()


def update_user_to_coach(user_id: int) -> dict:
    """
    Actualiza el rol de un usuario de cliente (1) a coach (2).
    
    Args:
        user_id (int): ID del usuario a actualizar
        
    Returns:
        dict: Resultado de la operación
    """
    try:
        connection = obtener_conexion()
        cursor = connection.cursor()
        
        # Verificar que el usuario existe y es un cliente
        check_query = """
        SELECT role 
        FROM users 
        WHERE id = %s
        """
        cursor.execute(check_query, (user_id,))
        result = cursor.fetchone()
        
        if not result:
            return {
                "success": False,
                "message": "User not found"
            }
            
        if result[0] != 1:
            return {
                "success": False,
                "message": "User is not a client"
            }
            
        # Actualizar el rol a coach
        update_query = """
        UPDATE users 
        SET role = 2 
        WHERE id = %s
        """
        cursor.execute(update_query, (user_id,))
        connection.commit()
        
        return {
            "success": True,
            "message": "User role updated to coach successfully"
        }
        
    except Exception as e:
        print(f"Error actualizando rol de usuario: {str(e)}")
        return {
            "success": False,
            "message": "Database error"
        }
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()


def get_user_details(user_id: int) -> dict:
    """
    Obtiene los detalles de un usuario según su rol, incluyendo información de membresía.
    """
    try:
        connection = obtener_conexion()
        cursor = connection.cursor(dictionary=True)
        
        # Datos básicos del usuario
        base_query = """
        SELECT 
            u.id,
            u.name,
            u.bio,
            u.image_url,
            u.role
        FROM users u
        WHERE u.id = %s
        """
        cursor.execute(base_query, (user_id,))
        user = cursor.fetchone()
        
        if not user:
            return None
            
        # Información de membresía
        membership_query = """
        SELECT 
            m.membership_name,
            pm.expiry_date,
            DATEDIFF(pm.expiry_date, CURDATE()) as days_remaining
        FROM paid_memberships pm
        JOIN memberships m ON pm.membership_id = m.id
        WHERE pm.user_id = %s
        AND pm.expiry_date >= CURDATE()
        ORDER BY pm.expiry_date DESC
        LIMIT 1
        """
        
        cursor.execute(membership_query, (user_id,))
        membership = cursor.fetchone()
        
        # Procesar información de membresía
        if membership and membership['days_remaining'] > 0:
            user['membership_days_remaining'] = membership['days_remaining']
            user['membership_expiry_date'] = membership['expiry_date'].isoformat()
        else:
            user['membership_days_remaining'] = 0
            user['membership_expiry_date'] = None
        
        # Datos específicos según el rol
        if user['role'] == 2:  # Coach
            coach_query = """
            SELECT COUNT(DISTINCT client_id) as client_count
            FROM coach_clients
            WHERE coach_id = %s
            """
            cursor.execute(coach_query, (user_id,))
            coach_data = cursor.fetchone()
            
            user.update({
                "role": "coach",
                "client_count": coach_data['client_count'] if coach_data else 0
            })
            
        elif user['role'] == 1:  # Cliente
            client_query = """
            SELECT COUNT(*) as workout_count
            FROM workouts w
            WHERE w.user_id = %s
            """
            cursor.execute(client_query, (user_id,))
            client_data = cursor.fetchone()
            
            user.update({
                "role": "client",
                "workout_count": client_data['workout_count'] if client_data else 0
            })
        
        print("DEBUG - Database user:", user)  # Debug para ver los datos antes de devolverlos
        return user
        
    except Exception as e:
        print(f"Error obteniendo detalles del usuario: {str(e)}")
        return None
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()


def demote_coach_to_client(user_id: int) -> dict:
    """
    Actualiza el rol de un usuario de coach (2) a cliente (1).
    
    Args:
        user_id (int): ID del usuario a actualizar
        
    Returns:
        dict: Resultado de la operación
    """
    try:
        connection = obtener_conexion()
        cursor = connection.cursor()
        
        # Verificar que el usuario existe y es un coach
        check_query = """
        SELECT role 
        FROM users 
        WHERE id = %s
        """
        cursor.execute(check_query, (user_id,))
        result = cursor.fetchone()
        
        if not result:
            return {
                "success": False,
                "message": "User not found"
            }
            
        if result[0] != 2:
            return {
                "success": False,
                "message": "User is not a coach"
            }
            
        # Primero eliminar todas las relaciones coach-cliente
        delete_relations_query = """
        DELETE FROM coach_clients 
        WHERE coach_id = %s
        """
        cursor.execute(delete_relations_query, (user_id,))
        
        # Actualizar el rol a cliente
        update_query = """
        UPDATE users 
        SET role = 1 
        WHERE id = %s
        """
        cursor.execute(update_query, (user_id,))
        connection.commit()
        
        return {
            "success": True,
            "message": "Coach demoted to client successfully"
        }
        
    except Exception as e:
        print(f"Error degradando coach: {str(e)}")
        return {
            "success": False,
            "message": "Database error"
        }
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()


def get_coach_routines_by_id(coach_id: int):
    """
    Consulta las rutinas de un coach específico.
    
    Args:
        coach_id (int): ID del coach
        
    Returns:
        list: Lista de rutinas del coach
    """
    try:
        connection = obtener_conexion()
        cursor = connection.cursor(dictionary=True)
        
        # Primero verificar que el usuario existe y es un coach
        check_query = """
        SELECT role 
        FROM users 
        WHERE id = %s AND role = 2
        """
        cursor.execute(check_query, (coach_id,))
        if not cursor.fetchone():
            return None
            
        # Obtener las rutinas
        query = """
        SELECT 
            r.id,
            r.name,
            r.description,
            r.created_at,
            (
                SELECT COUNT(DISTINCT ur.user_id)
                FROM user_routines ur
                WHERE ur.routine_id = r.id
            ) as assigned_clients_count
        FROM routines r
        WHERE r.coach_id = %s
        ORDER BY r.created_at DESC
        """
        cursor.execute(query, (coach_id,))
        routines = cursor.fetchall()
        
        # Formatear las fechas a ISO string
        for routine in routines:
            if routine['created_at']:
                routine['created_at'] = routine['created_at'].isoformat()
        
        return routines
        
    except Exception as e:
        print(f"Error obteniendo rutinas del coach: {str(e)}")
        return None
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()



def delete_routine_by_admin(routine_id: int) -> dict:
    """
    Elimina una rutina y sus ejercicios asociados (por un administrador).
    
    Args:
        routine_id (int): ID de la rutina a eliminar
        
    Returns:
        dict: Resultado de la operación
    """
    try:
        connection = obtener_conexion()
        cursor = connection.cursor()
        
        # Verificar que la rutina existe
        check_query = """
        SELECT id FROM routines WHERE id = %s
        """
        cursor.execute(check_query, (routine_id,))
        if not cursor.fetchone():
            return {
                "success": False,
                "message": "Routine not found"
            }
            
        # Eliminar registros relacionados en orden
        # 1. Eliminar sets de ejercicios de la rutina
        cursor.execute("""
            DELETE wes FROM workout_exercise_sets wes
            INNER JOIN workout_exercises we ON wes.workout_exercise_id = we.id
            INNER JOIN workouts w ON we.workout_id = w.id
            WHERE w.routine_id = %s
        """, (routine_id,))
        
        # 2. Eliminar ejercicios de workouts
        cursor.execute("""
            DELETE we FROM workout_exercises we
            INNER JOIN workouts w ON we.workout_id = w.id
            WHERE w.routine_id = %s
        """, (routine_id,))
        
        # 3. Eliminar workouts
        cursor.execute("""
            DELETE FROM workouts WHERE routine_id = %s
        """, (routine_id,))
        
        # 4. Eliminar asignaciones de rutinas a usuarios
        cursor.execute("""
            DELETE FROM user_routines WHERE routine_id = %s
        """, (routine_id,))
        
        # 5. Eliminar ejercicios de la rutina
        cursor.execute("""
            DELETE FROM routine_exercises WHERE routine_id = %s
        """, (routine_id,))
        
        # 6. Finalmente, eliminar la rutina
        cursor.execute("""
            DELETE FROM routines WHERE id = %s
        """, (routine_id,))
        
        connection.commit()
        
        return {
            "success": True,
            "message": "Routine and all associated data deleted successfully"
        }
        
    except Exception as e:
        print(f"Error eliminando rutina: {str(e)}")
        if 'connection' in locals():
            connection.rollback()
        return {
            "success": False,
            "message": f"Database error: {str(e)}"
        }
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()


def get_active_memberships():
    """
    Obtiene todas las membresías.
    
    Returns:
        list: Lista de membresías con sus detalles
    """
    try:
        connection = obtener_conexion()
        cursor = connection.cursor(dictionary=True)
        
        query = """
        SELECT 
            id,
            membership_name,
            price,
            days,
            active
        FROM memberships
        ORDER BY days ASC
        """
        
        cursor.execute(query)
        memberships = cursor.fetchall()
        
        return memberships
        
    except Exception as e:
        print(f"Error obteniendo membresías: {str(e)}")
        return None
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()


def get_membership_by_id(membership_id: int) -> dict:
    """
    Obtiene los detalles de una membresía por su ID.
    
    Args:
        membership_id (int): ID de la membresía a consultar
        
    Returns:
        dict: Detalles de la membresía
    """
    try:
        connection = obtener_conexion()
        cursor = connection.cursor(dictionary=True)
        
        query = """
        SELECT 
            id,
            membership_name,
            price,
            days,
            active
        FROM memberships
        WHERE id = %s
        """
        
        cursor.execute(query, (membership_id,))
        membership = cursor.fetchone()
        
        return membership
        
    except Exception as e:
        print(f"Error obteniendo membresía: {str(e)}")
        return None
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()


def update_membership(membership_id: int, membership_data: dict) -> dict:
    """
    Actualiza los datos de una membresía.
    
    Args:
        membership_id (int): ID de la membresía a actualizar
        membership_data (dict): Datos nuevos de la membresía
        
    Returns:
        dict: Resultado de la operación
    """
    try:
        connection = obtener_conexion()
        cursor = connection.cursor()
        
        # Verificar que la membresía existe
        check_query = """
        SELECT id FROM memberships WHERE id = %s
        """
        cursor.execute(check_query, (membership_id,))
        if not cursor.fetchone():
            return {
                "success": False,
                "message": "Membership not found"
            }
            
        # Actualizar la membresía
        update_query = """
        UPDATE memberships 
        SET 
            membership_name = %s,
            price = %s,
            days = %s,
            active = %s
        WHERE id = %s
        """
        
        cursor.execute(update_query, (
            membership_data['membership_name'],
            membership_data['price'],
            membership_data['days'],
            membership_data['active'],
            membership_id
        ))
        
        connection.commit()
        
        return {
            "success": True,
            "message": "Membership updated successfully"
        }
        
    except Exception as e:
        print(f"Error actualizando membresía: {str(e)}")
        return {
            "success": False,
            "message": f"Database error: {str(e)}"
        }
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()


def create_membership(membership_data: dict) -> dict:
    """
    Crea una nueva membresía.
    
    Args:
        membership_data (dict): Datos de la nueva membresía
        
    Returns:
        dict: Resultado de la operación
    """
    try:
        connection = obtener_conexion()
        cursor = connection.cursor()
        
        # Insertar la nueva membresía
        insert_query = """
        INSERT INTO memberships 
            (membership_name, price, days, active)
        VALUES 
            (%s, %s, %s, %s)
        """
        
        cursor.execute(insert_query, (
            membership_data['membership_name'],
            membership_data['price'],
            membership_data['days'],
            membership_data['active']
        ))
        
        connection.commit()
        
        return {
            "success": True,
            "message": "Membership created successfully",
            "id": cursor.lastrowid
        }
        
    except Exception as e:
        print(f"Error creando membresía: {str(e)}")
        return {
            "success": False,
            "message": f"Database error: {str(e)}"
        }
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()


def register_membership_payment(user_id: int, membership_id: int, payment_method: int) -> dict:
    """
    Registra un nuevo pago de membresía para un usuario.
    
    Args:
        user_id (int): ID del usuario
        membership_id (int): ID de la membresía pagada
        payment_method (int): Método de pago (1: Efectivo, 2: Tarjeta, etc.)
        
    Returns:
        dict: Resultado de la operación
    """
    try:
        connection = obtener_conexion()
        cursor = connection.cursor()
        
        # Verificar que la membresía existe y está activa
        check_membership = """
        SELECT days FROM memberships 
        WHERE id = %s AND active = TRUE
        """
        cursor.execute(check_membership, (membership_id,))
        membership = cursor.fetchone()
        
        if not membership:
            return {
                "success": False,
                "message": "Invalid or inactive membership"
            }
            
        days_to_add = membership[0]
        
        # Obtener la última membresía activa del usuario (si existe)
        check_active = """
        SELECT expiry_date 
        FROM paid_memberships 
        WHERE user_id = %s 
        AND expiry_date >= CURDATE()
        ORDER BY expiry_date DESC 
        LIMIT 1
        """
        cursor.execute(check_active, (user_id,))
        active_membership = cursor.fetchone()
        
        # Calcular nueva fecha de expiración
        if active_membership:
            # Si tiene membresía activa, añadir días a la fecha de expiración actual
            insert_query = """
            INSERT INTO paid_memberships 
                (membership_id, user_id, date, expiry_date, payment_method)
            VALUES 
                (%s, %s, CURDATE(), DATE_ADD(%s, INTERVAL %s DAY), %s)
            """
            cursor.execute(insert_query, (
                membership_id,
                user_id,
                active_membership[0],
                days_to_add,
                payment_method
            ))
        else:
            # Si no tiene membresía activa, añadir días a la fecha actual
            insert_query = """
            INSERT INTO paid_memberships 
                (membership_id, user_id, date, expiry_date, payment_method)
            VALUES 
                (%s, %s, CURDATE(), DATE_ADD(CURDATE(), INTERVAL %s DAY), %s)
            """
            cursor.execute(insert_query, (
                membership_id,
                user_id,
                days_to_add,
                payment_method
            ))
        
        connection.commit()
        
        return {
            "success": True,
            "message": "Membership payment registered successfully"
        }
        
    except Exception as e:
        print(f"Error registrando pago de membresía: {str(e)}")
        if 'connection' in locals():
            connection.rollback()
        return {
            "success": False,
            "message": f"Database error: {str(e)}"
        }
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()


def get_user_membership_days(user_id: int) -> dict:
    """
    Obtiene los días restantes y fecha de expiración de la membresía de un usuario.
    
    Args:
        user_id (int): ID del usuario
        
    Returns:
        dict: Información de la membresía del usuario
    """
    try:
        connection = obtener_conexion()
        cursor = connection.cursor(dictionary=True)
        
        query = """
        SELECT 
            m.membership_name,
            pm.expiry_date,
            GREATEST(DATEDIFF(pm.expiry_date, CURDATE()), 0) as days_remaining
        FROM paid_memberships pm
        JOIN memberships m ON pm.membership_id = m.id
        WHERE pm.user_id = %s
        AND pm.expiry_date >= CURDATE()
        ORDER BY pm.expiry_date DESC
        LIMIT 1
        """
        
        cursor.execute(query, (user_id,))
        membership = cursor.fetchone()
        
        if membership and membership['days_remaining'] >= 0:
            return {
                "has_active_membership": True,
                "membership_name": membership['membership_name'],
                "expiry_date": membership['expiry_date'].isoformat(),
                "days_remaining": membership['days_remaining']
            }
        
        return {
            "has_active_membership": False,
            "message": "No hay membresías activas"
        }
        
    except Exception as e:
        print(f"Error consultando membresía: {str(e)}")
        return None
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()



def revoke_user_membership(user_id: int) -> dict:
    """
    Revoca todas las membresías activas de un usuario estableciendo sus fechas de expiración
    a la fecha actual, dejando los días restantes en 0.
    
    Args:
        user_id (int): ID del usuario
        
    Returns:
        dict: Resultado de la operación
    """
    try:
        connection = obtener_conexion()
        cursor = connection.cursor()
        
        # Verificar si el usuario tiene membresías activas
        check_active = """
        SELECT COUNT(*) 
        FROM paid_memberships 
        WHERE user_id = %s 
        AND expiry_date >= CURDATE()
        """
        cursor.execute(check_active, (user_id,))
        active_count = cursor.fetchone()[0]
        
        if active_count == 0:
            return {
                "success": False,
                "message": "User has no active memberships"
            }
            
        # Actualizar la fecha de expiración a la fecha actual para todas las membresías activas
        update_query = """
        UPDATE paid_memberships 
        SET expiry_date = CURDATE()
        WHERE user_id = %s 
        AND expiry_date >= CURDATE()
        """
        cursor.execute(update_query, (user_id,))
        
        connection.commit()
        
        return {
            "success": True,
            "message": f"Successfully revoked {active_count} active membership(s)"
        }
        
    except Exception as e:
        print(f"Error revocando membresías: {str(e)}")
        if 'connection' in locals():
            connection.rollback()
        return {
            "success": False,
            "message": f"Database error: {str(e)}"
        }
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()


def get_membership_stats_by_week():
    """
    Obtiene el total de pagos en efectivo por día en los últimos 7 días.
    """
    try:
        connection = obtener_conexion()
        cursor = connection.cursor(dictionary=True)
        
        query = """
        WITH RECURSIVE dates AS (
            SELECT DATE_ADD(CURDATE(), INTERVAL 0 DAY) as date
            UNION ALL
            SELECT DATE_SUB(date, INTERVAL 1 DAY)
            FROM dates
            WHERE DATE_SUB(date, INTERVAL 1 DAY) >= DATE_SUB(CURDATE(), INTERVAL 6 DAY)
        )
        SELECT 
            dates.date as date,
            COALESCE(SUM(m.price), 0) as total
        FROM dates
        LEFT JOIN paid_memberships pm ON DATE(pm.date) = dates.date 
            AND pm.payment_method = 1
        LEFT JOIN memberships m ON pm.membership_id = m.id
        GROUP BY dates.date
        ORDER BY dates.date DESC;
        """
        
        cursor.execute(query)
        results = cursor.fetchall()
        
        # Formatear las fechas a string y asegurar que total sea float
        formatted_results = []
        for i, row in enumerate(results, 1):
            formatted_results.append({
                'id': i,
                'date': row['date'].strftime('%Y-%m-%d'),
                'total': float(row['total']) if row['total'] else 0.0
            })
            
        return formatted_results
        
    except Exception as e:
        print(f"Error obteniendo estadísticas semanales: {str(e)}")
        return None
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()

def get_membership_stats_by_month():
    """
    Obtiene el total de pagos en efectivo por día en los últimos 30 días.
    """
    try:
        connection = obtener_conexion()
        cursor = connection.cursor(dictionary=True)
        
        query = """
        WITH RECURSIVE dates AS (
            SELECT DATE_ADD(CURDATE(), INTERVAL 0 DAY) as date
            UNION ALL
            SELECT DATE_SUB(date, INTERVAL 1 DAY)
            FROM dates
            WHERE DATE_SUB(date, INTERVAL 1 DAY) >= DATE_SUB(CURDATE(), INTERVAL 29 DAY)
        )
        SELECT 
            dates.date as date,
            COALESCE(SUM(m.price), 0) as total
        FROM dates
        LEFT JOIN paid_memberships pm ON DATE(pm.date) = dates.date 
            AND pm.payment_method = 1
        LEFT JOIN memberships m ON pm.membership_id = m.id
        GROUP BY dates.date
        ORDER BY dates.date DESC;
        """
        
        cursor.execute(query)
        results = cursor.fetchall()
        
        # Formatear las fechas a string y asegurar que total sea float
        formatted_results = []
        for i, row in enumerate(results, 1):
            formatted_results.append({
                'id': i,
                'date': row['date'].strftime('%Y-%m-%d'),
                'total': float(row['total']) if row['total'] else 0.0
            })
            
        return formatted_results
        
    except Exception as e:
        print(f"Error obteniendo estadísticas mensuales: {str(e)}")
        return None
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()

def get_membership_stats_by_year():
    """
    Obtiene el total de pagos en efectivo por mes en los últimos 12 meses.
    """
    try:
        connection = obtener_conexion()
        cursor = connection.cursor(dictionary=True)
        
        query = """
        WITH RECURSIVE months AS (
            SELECT 
                DATE_FORMAT(CURDATE(), '%Y-%m-01') as date
            UNION ALL
            SELECT DATE_SUB(date, INTERVAL 1 MONTH)
            FROM months
            WHERE DATE_SUB(date, INTERVAL 1 MONTH) >= 
                  DATE_SUB(DATE_FORMAT(CURDATE(), '%Y-%m-01'), INTERVAL 11 MONTH)
        )
        SELECT 
            DATE_FORMAT(months.date, '%Y-%m') as date,
            COALESCE(SUM(m.price), 0) as total
        FROM months
        LEFT JOIN paid_memberships pm 
            ON DATE_FORMAT(pm.date, '%Y-%m') = DATE_FORMAT(months.date, '%Y-%m')
            AND pm.payment_method = 1
        LEFT JOIN memberships m ON pm.membership_id = m.id
        GROUP BY months.date
        ORDER BY months.date DESC;
        """
        
        cursor.execute(query)
        results = cursor.fetchall()
        
        # Formatear y asegurar que total sea float
        formatted_results = []
        for i, row in enumerate(results, 1):
            formatted_results.append({
                'id': i,
                'date': row['date'],
                'total': float(row['total']) if row['total'] else 0.0
            })
            
        return formatted_results
        
    except Exception as e:
        print(f"Error obteniendo estadísticas anuales: {str(e)}")
        return None
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()

def get_online_membership_stats_by_week():
    """
    Obtiene el total de pagos en línea por día en los últimos 7 días.
    """
    try:
        connection = obtener_conexion()
        cursor = connection.cursor(dictionary=True)
        
        query = """
        WITH RECURSIVE dates AS (
            SELECT DATE_ADD(CURDATE(), INTERVAL 0 DAY) as date
            UNION ALL
            SELECT DATE_SUB(date, INTERVAL 1 DAY)
            FROM dates
            WHERE DATE_SUB(date, INTERVAL 1 DAY) >= DATE_SUB(CURDATE(), INTERVAL 6 DAY)
        )
        SELECT 
            dates.date as date,
            COALESCE(SUM(m.price), 0) as total
        FROM dates
        LEFT JOIN paid_memberships pm ON DATE(pm.date) = dates.date 
            AND pm.payment_method = 2
        LEFT JOIN memberships m ON pm.membership_id = m.id
        GROUP BY dates.date
        ORDER BY dates.date DESC;
        """
        
        cursor.execute(query)
        results = cursor.fetchall()
        
        # Formatear las fechas a string y asegurar que total sea float
        formatted_results = []
        for i, row in enumerate(results, 1):
            formatted_results.append({
                'id': i,
                'date': row['date'].strftime('%Y-%m-%d'),
                'total': float(row['total']) if row['total'] else 0.0
            })
            
        return formatted_results
        
    except Exception as e:
        print(f"Error obteniendo estadísticas semanales online: {str(e)}")
        return None
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()

def get_online_membership_stats_by_month():
    """
    Obtiene el total de pagos en línea por día en los últimos 30 días.
    """
    try:
        connection = obtener_conexion()
        cursor = connection.cursor(dictionary=True)
        
        query = """
        WITH RECURSIVE dates AS (
            SELECT DATE_ADD(CURDATE(), INTERVAL 0 DAY) as date
            UNION ALL
            SELECT DATE_SUB(date, INTERVAL 1 DAY)
            FROM dates
            WHERE DATE_SUB(date, INTERVAL 1 DAY) >= DATE_SUB(CURDATE(), INTERVAL 29 DAY)
        )
        SELECT 
            dates.date as date,
            COALESCE(SUM(m.price), 0) as total
        FROM dates
        LEFT JOIN paid_memberships pm ON DATE(pm.date) = dates.date 
            AND pm.payment_method = 2
        LEFT JOIN memberships m ON pm.membership_id = m.id
        GROUP BY dates.date
        ORDER BY dates.date DESC;
        """
        
        cursor.execute(query)
        results = cursor.fetchall()
        
        # Formatear las fechas a string y asegurar que total sea float
        formatted_results = []
        for i, row in enumerate(results, 1):
            formatted_results.append({
                'id': i,
                'date': row['date'].strftime('%Y-%m-%d'),
                'total': float(row['total']) if row['total'] else 0.0
            })
            
        return formatted_results
        
    except Exception as e:
        print(f"Error obteniendo estadísticas mensuales online: {str(e)}")
        return None
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()

def get_online_membership_stats_by_year():
    """
    Obtiene el total de pagos en línea por mes en los últimos 12 meses.
    """
    try:
        connection = obtener_conexion()
        cursor = connection.cursor(dictionary=True)
        
        query = """
        WITH RECURSIVE months AS (
            SELECT 
                DATE_FORMAT(DATE_ADD(CURDATE(), INTERVAL 0 DAY), '%Y-%m-01') as date
            UNION ALL
            SELECT DATE_SUB(date, INTERVAL 1 MONTH)
            FROM months
            WHERE DATE_SUB(date, INTERVAL 1 MONTH) >= 
                  DATE_SUB(DATE_FORMAT(CURDATE(), '%Y-%m-01'), INTERVAL 11 MONTH)
        )
        SELECT 
            DATE_FORMAT(months.date, '%Y-%m') as date,
            COALESCE(SUM(m.price), 0) as total
        FROM months
        LEFT JOIN paid_memberships pm 
            ON DATE_FORMAT(pm.date, '%Y-%m') = DATE_FORMAT(months.date, '%Y-%m')
            AND pm.payment_method = 2
        LEFT JOIN memberships m ON pm.membership_id = m.id
        GROUP BY months.date
        ORDER BY months.date DESC;
        """
        
        cursor.execute(query)
        results = cursor.fetchall()
        
        # Formatear y asegurar que total sea float
        formatted_results = []
        for i, row in enumerate(results, 1):
            formatted_results.append({
                'id': i,
                'date': row['date'],
                'total': float(row['total']) if row['total'] else 0.0
            })
            
        return formatted_results
        
    except Exception as e:
        print(f"Error obteniendo estadísticas anuales online: {str(e)}")
        return None
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()

def get_all_membership_stats_by_week():
    """
    Obtiene el total de todos los pagos por día en los últimos 7 días.
    """
    try:
        connection = obtener_conexion()
        cursor = connection.cursor(dictionary=True)
        
        query = """
        WITH RECURSIVE dates AS (
            SELECT DATE_ADD(CURDATE(), INTERVAL 0 DAY) as date
            UNION ALL
            SELECT DATE_SUB(date, INTERVAL 1 DAY)
            FROM dates
            WHERE DATE_SUB(date, INTERVAL 1 DAY) >= DATE_SUB(CURDATE(), INTERVAL 6 DAY)
        )
        SELECT 
            dates.date as date,
            COALESCE(SUM(m.price), 0) as total
        FROM dates
        LEFT JOIN paid_memberships pm ON DATE(pm.date) = dates.date 
        LEFT JOIN memberships m ON pm.membership_id = m.id
        GROUP BY dates.date
        ORDER BY dates.date DESC
        """
        
        cursor.execute(query)
        results = cursor.fetchall()
        
        formatted_results = []
        for i, row in enumerate(results, 1):
            formatted_results.append({
                'id': i,
                'date': row['date'].strftime('%Y-%m-%d'),
                'total': float(row['total']) if row['total'] else 0.0
            })
            
        return formatted_results
        
    except Exception as e:
        print(f"Error obteniendo estadísticas semanales totales: {str(e)}")
        return None
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()

def get_all_membership_stats_by_month():
    """
    Obtiene el total de todos los pagos por día en los últimos 30 días.
    """
    try:
        connection = obtener_conexion()
        cursor = connection.cursor(dictionary=True)
        
        query = """
        WITH RECURSIVE dates AS (
            SELECT DATE_ADD(CURDATE(), INTERVAL 0 DAY) as date
            UNION ALL
            SELECT DATE_SUB(date, INTERVAL 1 DAY)
            FROM dates
            WHERE DATE_SUB(date, INTERVAL 1 DAY) >= DATE_SUB(CURDATE(), INTERVAL 29 DAY)
        )
        SELECT 
            dates.date as date,
            COALESCE(SUM(m.price), 0) as total
        FROM dates
        LEFT JOIN paid_memberships pm ON DATE(pm.date) = dates.date 
        LEFT JOIN memberships m ON pm.membership_id = m.id
        GROUP BY dates.date
        ORDER BY dates.date DESC
        """
        
        cursor.execute(query)
        results = cursor.fetchall()
        
        formatted_results = []
        for i, row in enumerate(results, 1):
            formatted_results.append({
                'id': i,
                'date': row['date'].strftime('%Y-%m-%d'),
                'total': float(row['total']) if row['total'] else 0.0
            })
            
        return formatted_results
        
    except Exception as e:
        print(f"Error obteniendo estadísticas mensuales totales: {str(e)}")
        return None
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()

def get_all_membership_stats_by_year():
    """
    Obtiene el total de todos los pagos por mes en los últimos 12 meses.
    """
    try:
        connection = obtener_conexion()
        cursor = connection.cursor(dictionary=True)
        
        query = """
        WITH RECURSIVE months AS (
            SELECT 
                DATE_FORMAT(DATE_ADD(CURDATE(), INTERVAL 0 DAY), '%Y-%m-01') as date
            UNION ALL
            SELECT DATE_SUB(date, INTERVAL 1 MONTH)
            FROM months
            WHERE DATE_SUB(date, INTERVAL 1 MONTH) >= 
                  DATE_SUB(DATE_FORMAT(CURDATE(), '%Y-%m-01'), INTERVAL 11 MONTH)
        )
        SELECT 
            DATE_FORMAT(months.date, '%Y-%m') as date,
            COALESCE(SUM(m.price), 0) as total
        FROM months
        LEFT JOIN paid_memberships pm 
            ON DATE_FORMAT(pm.date, '%Y-%m') = DATE_FORMAT(months.date, '%Y-%m')
        LEFT JOIN memberships m ON pm.membership_id = m.id
        GROUP BY months.date
        ORDER BY months.date DESC
        """
        
        cursor.execute(query)
        results = cursor.fetchall()
        
        formatted_results = []
        for i, row in enumerate(results, 1):
            formatted_results.append({
                'id': i,
                'date': row['date'],
                'total': float(row['total']) if row['total'] else 0.0
            })
            
        return formatted_results
        
    except Exception as e:
        print(f"Error obteniendo estadísticas anuales totales: {str(e)}")
        return None
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()



# Para pruebas locales
if __name__ == "__main__":
    print(get_user_routines(16))


def get_workout_detail(workout_id: int):
    """
    Obtiene la información detallada de un workout específico, incluyendo sus ejercicios y sets.
    Calcula el volumen total basado en peso * repeticiones de cada set.
    
    Args:
        workout_id (int): ID del workout a consultar
        
    Returns:
        dict: Información detallada del workout con sus ejercicios y sets
    """
    try:
        connection = obtener_conexion()
        cursor = connection.cursor(dictionary=True)
        
        # Obtener información básica del workout
        workout_query = """
        SELECT 
            w.id,
            w.name,
            w.description,
            w.date,
            w.time,
            COALESCE(
                (SELECT SUM(wes.weight * wes.reps)
                FROM workout_exercises we2
                JOIN workout_exercise_sets wes ON we2.id = wes.workout_exercise_id
                WHERE we2.workout_id = w.id),
                0
            ) as total_volume
        FROM workouts w
        WHERE w.id = %s
        """
        cursor.execute(workout_query, (workout_id,))
        workout = cursor.fetchone()
        
        if not workout:
            return None
            
        # Formatear la fecha
        workout['date'] = workout['date'].isoformat() if workout['date'] else None
        
        # Obtener ejercicios con sus sets y calcular volumen por ejercicio
        exercises_query = """
        SELECT 
            we.id,
            e.name,
            e.image_url,
            we.sets,
            we.position,
            wes.set_number,
            wes.weight,
            wes.reps,
            (SELECT SUM(wes2.weight * wes2.reps)
             FROM workout_exercise_sets wes2
             WHERE wes2.workout_exercise_id = we.id) as exercise_volume
        FROM workout_exercises we
        JOIN exercises e ON we.exercise_id = e.id
        LEFT JOIN workout_exercise_sets wes ON we.id = wes.workout_exercise_id
        WHERE we.workout_id = %s
        ORDER BY we.position, wes.set_number
        """
        cursor.execute(exercises_query, (workout_id,))
        exercise_rows = cursor.fetchall()
        
        # Estructurar los ejercicios y sus sets
        exercises = {}
        for row in exercise_rows:
            exercise_id = row['id']
            if exercise_id not in exercises:
                exercises[exercise_id] = {
                    'id': exercise_id,
                    'name': row['name'],
                    'image_url': row['image_url'],
                    'sets': row['sets'],
                    'position': row['position'],
                    'volume': row['exercise_volume'],  # Volumen por ejercicio
                    'exercise_sets': []
                }
            
            if row['set_number'] is not None:
                set_volume = row['weight'] * row['reps']  # Volumen del set individual
                exercises[exercise_id]['exercise_sets'].append({
                    'set_number': row['set_number'],
                    'weight': row['weight'],
                    'reps': row['reps'],
                    'volume': set_volume  # Volumen del set
                })
        
        # Agregar la lista de ejercicios al workout
        workout['exercises'] = list(exercises.values())
        
        return workout
        
    except Exception as e:
        print(f"Error obteniendo detalle del workout: {str(e)}")
        return None
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()


def get_user_workouts(user_id: int):
    """
    Obtiene la lista de workouts de un usuario específico.
    
    Args:
        user_id (int): ID del usuario
        
    Returns:
        list: Lista de workouts con información básica
    """
    try:
        connection = obtener_conexion()
        cursor = connection.cursor(dictionary=True)
        
        query = """
        SELECT 
            id,
            name,
            date
        FROM workouts 
        WHERE user_id = %s
        ORDER BY date DESC
        """
        
        cursor.execute(query, (user_id,))
        workouts = cursor.fetchall()
        
        # Formatear las fechas
        for workout in workouts:
            workout['date'] = workout['date'].isoformat() if workout['date'] else None
            
        return workouts
        
    except Exception as e:
        print(f"Error obteniendo workouts del usuario: {str(e)}")
        return None
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()


def get_workouts_volume_by_week(user_id: int):
    """
    Obtiene el volumen total de entrenamiento por día en los últimos 7 días para un usuario específico.
    """
    try:
        connection = obtener_conexion()
        cursor = connection.cursor(dictionary=True)
        
        query = """
        WITH RECURSIVE dates AS (
            SELECT DATE_ADD(CURDATE(), INTERVAL 0 DAY) as date
            UNION ALL
            SELECT DATE_SUB(date, INTERVAL 1 DAY)
            FROM dates
            WHERE DATE_SUB(date, INTERVAL 1 DAY) >= DATE_SUB(CURDATE(), INTERVAL 6 DAY)
        )
        SELECT 
            dates.date as date,
            COALESCE(SUM(wes.weight * wes.reps), 0) as total_volume
        FROM dates
        LEFT JOIN workouts w ON DATE(w.date) = dates.date AND w.user_id = %s
        LEFT JOIN workout_exercises we ON w.id = we.workout_id
        LEFT JOIN workout_exercise_sets wes ON we.id = wes.workout_exercise_id
        GROUP BY dates.date
        ORDER BY dates.date DESC;
        """
        
        cursor.execute(query, (user_id,))
        results = cursor.fetchall()
        
        # Formatear las fechas a string y asegurar que total_volume sea float
        formatted_results = [
            {'date': row['date'].strftime('%Y-%m-%d'), 'total_volume': float(row['total_volume'])}
            for row in results
        ]
        
        return formatted_results
        
    except Exception as e:
        print(f"Error obteniendo volumen semanal: {str(e)}")
        return None
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()

def get_workouts_volume_by_month(user_id: int):
    """
    Obtiene el volumen total de entrenamiento por día en los últimos 30 días para un usuario específico.
    """
    try:
        connection = obtener_conexion()
        cursor = connection.cursor(dictionary=True)
        
        query = """
        WITH RECURSIVE dates AS (
            SELECT DATE_ADD(CURDATE(), INTERVAL 0 DAY) as date
            UNION ALL
            SELECT DATE_SUB(date, INTERVAL 1 DAY)
            FROM dates
            WHERE DATE_SUB(date, INTERVAL 1 DAY) >= DATE_SUB(CURDATE(), INTERVAL 29 DAY)
        )
        SELECT 
            dates.date as date,
            COALESCE(SUM(wes.weight * wes.reps), 0) as total_volume
        FROM dates
        LEFT JOIN workouts w ON DATE(w.date) = dates.date AND w.user_id = %s
        LEFT JOIN workout_exercises we ON w.id = we.workout_id
        LEFT JOIN workout_exercise_sets wes ON we.id = wes.workout_exercise_id
        GROUP BY dates.date
        ORDER BY dates.date DESC;
        """
        
        cursor.execute(query, (user_id,))
        results = cursor.fetchall()
        
        formatted_results = [
            {'date': row['date'].strftime('%Y-%m-%d'), 'total_volume': float(row['total_volume'])}
            for row in results
        ]
        
        return formatted_results
        
    except Exception as e:
        print(f"Error obteniendo volumen mensual: {str(e)}")
        return None
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()

def get_workouts_volume_by_year(user_id: int):
    """
    Obtiene el volumen total de entrenamiento por mes en los últimos 12 meses para un usuario específico.
    """
    try:
        connection = obtener_conexion()
        cursor = connection.cursor(dictionary=True)
        
        query = """
        WITH RECURSIVE months AS (
            SELECT DATE_FORMAT(CURDATE(), '%Y-%m-01') as date
            UNION ALL
            SELECT DATE_SUB(date, INTERVAL 1 MONTH)
            FROM months
            WHERE DATE_SUB(date, INTERVAL 1 MONTH) >= DATE_SUB(DATE_FORMAT(CURDATE(), '%Y-%m-01'), INTERVAL 11 MONTH)
        )
        SELECT 
            DATE_FORMAT(months.date, '%Y-%m') as date,
            COALESCE(SUM(wes.weight * wes.reps), 0) as total_volume
        FROM months
        LEFT JOIN workouts w ON DATE_FORMAT(w.date, '%Y-%m') = DATE_FORMAT(months.date, '%Y-%m') AND w.user_id = %s
        LEFT JOIN workout_exercises we ON w.id = we.workout_id
        LEFT JOIN workout_exercise_sets wes ON we.id = wes.workout_exercise_id
        GROUP BY months.date
        ORDER BY months.date DESC;
        """
        
        cursor.execute(query, (user_id,))
        results = cursor.fetchall()
        
        formatted_results = [
            {'date': row['date'], 'total_volume': float(row['total_volume'])}
            for row in results
        ]
        
        return formatted_results
        
    except Exception as e:
        print(f"Error obteniendo volumen anual: {str(e)}")
        return None
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()

def get_volume_by_muscle_group_week(user_id: int):
    """
    Obtiene el volumen total de entrenamiento por grupo muscular en los últimos 7 días para un usuario específico.
    Incluye días sin entrenamiento.
    """
    try:
        connection = obtener_conexion()
        cursor = connection.cursor(dictionary=True)
        
        query = """
        WITH RECURSIVE dates AS (
            SELECT DATE_SUB(CURDATE(), INTERVAL 6 DAY) as date
            UNION ALL
            SELECT DATE_ADD(date, INTERVAL 1 DAY)
            FROM dates
            WHERE DATE_ADD(date, INTERVAL 1 DAY) <= CURDATE()
        )
        SELECT 
            dates.date as date,
            mg.id as muscle_group_id,
            mg.name as muscle_group,
            COALESCE(SUM(wes.weight * wes.reps), 0) as total_volume
        FROM dates
        LEFT JOIN workouts w ON DATE(w.date) = dates.date AND w.user_id = %s
        LEFT JOIN workout_exercises we ON w.id = we.workout_id
        LEFT JOIN workout_exercise_sets wes ON we.id = wes.workout_exercise_id
        LEFT JOIN exercises e ON we.exercise_id = e.id
        LEFT JOIN muscle_groups mg ON e.muscle_group_id = mg.id
        WHERE mg.id IS NOT NULL
        GROUP BY dates.date, mg.id, mg.name
        ORDER BY dates.date DESC, mg.name;
        """
        
        cursor.execute(query, (user_id,))
        results = cursor.fetchall()
        
        # Generar las últimas 7 fechas
        dates = [(datetime.now().date() - timedelta(days=i)).strftime('%Y-%m-%d') for i in range(6, -1, -1)]
        muscle_groups = {}
        
        for row in results:
            muscle_group_id = row['muscle_group_id']
            if muscle_group_id not in muscle_groups:
                muscle_groups[muscle_group_id] = {
                    "id": muscle_group_id,
                    "name": row['muscle_group'],
                    "volumes": [0] * 7,  # Inicializa con 7 días
                    "bestVolume": 0
                }
            
            # Calcula el índice basado en la diferencia de días desde la fecha más reciente
            date_index = dates.index(row['date'].strftime('%Y-%m-%d'))
            volume = float(row['total_volume'])
            muscle_groups[muscle_group_id]["volumes"][date_index] = volume
            muscle_groups[muscle_group_id]["bestVolume"] = max(muscle_groups[muscle_group_id]["bestVolume"], volume)
        
        formatted_results = {
            "dates": dates,
            "muscle_groups": list(muscle_groups.values())
        }
        
        return formatted_results
        
    except Exception as e:
        print(f"Error obteniendo volumen semanal por grupo muscular: {str(e)}")
        return None
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()

def get_volume_by_muscle_group_month(user_id: int):
    """
    Obtiene el volumen total de entrenamiento por grupo muscular en los últimos 30 días para un usuario específico.
    Incluye días sin entrenamiento.
    """
    try:
        connection = obtener_conexion()
        cursor = connection.cursor(dictionary=True)
        
        query = """
        WITH RECURSIVE dates AS (
            SELECT DATE_SUB(CURDATE(), INTERVAL 29 DAY) as date
            UNION ALL
            SELECT DATE_ADD(date, INTERVAL 1 DAY)
            FROM dates
            WHERE DATE_ADD(date, INTERVAL 1 DAY) <= CURDATE()
        )
        SELECT 
            dates.date as date,
            mg.id as muscle_group_id,
            mg.name as muscle_group,
            COALESCE(SUM(wes.weight * wes.reps), 0) as total_volume
        FROM dates
        LEFT JOIN workouts w ON DATE(w.date) = dates.date AND w.user_id = %s
        LEFT JOIN workout_exercises we ON w.id = we.workout_id
        LEFT JOIN workout_exercise_sets wes ON we.id = wes.workout_exercise_id
        LEFT JOIN exercises e ON we.exercise_id = e.id
        LEFT JOIN muscle_groups mg ON e.muscle_group_id = mg.id
        WHERE mg.id IS NOT NULL
        GROUP BY dates.date, mg.id, mg.name
        ORDER BY dates.date DESC, mg.name;
        """
        
        cursor.execute(query, (user_id,))
        results = cursor.fetchall()
        
        # Generar las últimas 30 fechas
        dates = [(datetime.now().date() - timedelta(days=i)).strftime('%Y-%m-%d') for i in range(29, -1, -1)]
        muscle_groups = {}
        
        for row in results:
            muscle_group_id = row['muscle_group_id']
            if muscle_group_id not in muscle_groups:
                muscle_groups[muscle_group_id] = {
                    "id": muscle_group_id,
                    "name": row['muscle_group'],
                    "volumes": [0] * 30,  # Inicializa con 30 días
                    "bestVolume": 0
                }
            
            # Calcula el índice basado en la diferencia de días desde la fecha más reciente
            date_index = dates.index(row['date'].strftime('%Y-%m-%d'))
            volume = float(row['total_volume'])
            muscle_groups[muscle_group_id]["volumes"][date_index] = volume
            muscle_groups[muscle_group_id]["bestVolume"] = max(muscle_groups[muscle_group_id]["bestVolume"], volume)
        
        formatted_results = {
            "dates": dates,
            "muscle_groups": list(muscle_groups.values())
        }
        
        return formatted_results
        
    except Exception as e:
        print(f"Error obteniendo volumen mensual por grupo muscular: {str(e)}")
        return None
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()

def get_volume_by_muscle_group_year(user_id: int):
    """
    Obtiene el volumen total de entrenamiento por grupo muscular en los últimos 12 meses para un usuario específico.
    Incluye meses sin entrenamiento.
    """
    try:
        connection = obtener_conexion()
        cursor = connection.cursor(dictionary=True)
        
        query = """
        WITH RECURSIVE months AS (
            SELECT DATE_FORMAT(DATE_SUB(CURDATE(), INTERVAL 11 MONTH), '%Y-%m-01') as date
            UNION ALL
            SELECT DATE_ADD(date, INTERVAL 1 MONTH)
            FROM months
            WHERE DATE_ADD(date, INTERVAL 1 MONTH) <= DATE_FORMAT(CURDATE(), '%Y-%m-01')
        )
        SELECT 
            DATE_FORMAT(months.date, '%Y-%m') as date,
            mg.id as muscle_group_id,
            mg.name as muscle_group,
            COALESCE(SUM(wes.weight * wes.reps), 0) as total_volume
        FROM months
        LEFT JOIN workouts w ON DATE_FORMAT(w.date, '%Y-%m') = DATE_FORMAT(months.date, '%Y-%m') AND w.user_id = %s
        LEFT JOIN workout_exercises we ON w.id = we.workout_id
        LEFT JOIN workout_exercise_sets wes ON we.id = wes.workout_exercise_id
        LEFT JOIN exercises e ON we.exercise_id = e.id
        LEFT JOIN muscle_groups mg ON e.muscle_group_id = mg.id
        WHERE mg.id IS NOT NULL
        GROUP BY months.date, mg.id, mg.name
        ORDER BY months.date DESC, mg.name;
        """
        
        cursor.execute(query, (user_id,))
        results = cursor.fetchall()
        
        # Generar los últimos 12 meses
        dates = [(datetime.now().replace(day=1) - timedelta(days=30*i)).strftime('%Y-%m') for i in range(11, -1, -1)]
        muscle_groups = {}
        
        for row in results:
            muscle_group_id = row['muscle_group_id']
            if muscle_group_id not in muscle_groups:
                muscle_groups[muscle_group_id] = {
                    "id": muscle_group_id,
                    "name": row['muscle_group'],
                    "volumes": [0] * 12,  # Inicializa con 12 meses
                    "bestVolume": 0
                }
            
            # Calcula el índice basado en la diferencia de meses desde el mes más reciente
            date_index = dates.index(row['date'])
            volume = float(row['total_volume'])
            muscle_groups[muscle_group_id]["volumes"][date_index] = volume
            muscle_groups[muscle_group_id]["bestVolume"] = max(muscle_groups[muscle_group_id]["bestVolume"], volume)
        
        formatted_results = {
            "dates": dates,
            "muscle_groups": list(muscle_groups.values())
        }
        
        return formatted_results
        
    except Exception as e:
        print(f"Error obteniendo volumen anual por grupo muscular: {str(e)}")
        return None
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()

def get_sets_by_muscle_group_week(user_id: int):
    """
    Obtiene el número total de sets por grupo muscular en los últimos 7 días para un usuario específico.
    Incluye días sin entrenamiento.
    """
    try:
        connection = obtener_conexion()
        with connection.cursor(dictionary=True) as cursor:
            query = """
            SELECT 
                DATE(w.date) as date,
                mg.id as muscle_group_id,
                mg.name as muscle_group,
                COALESCE(SUM(wes.reps), 0) as total_sets
            FROM workout_exercise_sets wes
            JOIN workout_exercises we ON wes.workout_exercise_id = we.id
            JOIN workouts w ON we.workout_id = w.id
            JOIN exercises e ON we.exercise_id = e.id
            JOIN muscle_groups mg ON e.muscle_group_id = mg.id
            WHERE w.user_id = %s AND DATE(w.date) >= DATE_SUB(CURDATE(), INTERVAL 6 DAY)
            GROUP BY DATE(w.date), mg.id, mg.name
            ORDER BY DATE(w.date) DESC, mg.name;
            """
            
            cursor.execute(query, (user_id,))
            results = cursor.fetchall()
            
            # Generar las últimas 7 fechas
            dates = [(datetime.now().date() - timedelta(days=i)).strftime('%Y-%m-%d') for i in range(6, -1, -1)]
            muscle_groups = {}
            
            for row in results:
                muscle_group_id = row['muscle_group_id']
                if muscle_group_id not in muscle_groups:
                    muscle_groups[muscle_group_id] = {
                        "id": muscle_group_id,
                        "name": row['muscle_group'],
                        "sets": [0] * 7,  # Inicializa con 7 días
                        "bestSets": 0
                    }
                
                # Calcula el índice basado en la diferencia de días desde la fecha más reciente
                date_index = dates.index(row['date'].strftime('%Y-%m-%d'))
                sets = int(row['total_sets'])
                muscle_groups[muscle_group_id]["sets"][date_index] = sets
                muscle_groups[muscle_group_id]["bestSets"] = max(muscle_groups[muscle_group_id]["bestSets"], sets)
            
            formatted_results = {
                "dates": dates,
                "muscle_groups": list(muscle_groups.values())
            }
            
            return formatted_results
    except Exception as e:
        print(f"Error obteniendo sets semanales por grupo muscular: {str(e)}")
        return None
    finally:
        if connection.is_connected():
            connection.close()

def get_sets_by_muscle_group_month(user_id: int):
    """
    Obtiene el número total de sets por grupo muscular en los últimos 30 días para un usuario específico.
    Incluye días sin entrenamiento.
    """
    try:
        connection = obtener_conexion()
        with connection.cursor(dictionary=True) as cursor:
            query = """
            SELECT 
                DATE(w.date) as date,
                mg.id as muscle_group_id,
                mg.name as muscle_group,
                COALESCE(SUM(wes.reps), 0) as total_sets
            FROM workout_exercise_sets wes
            JOIN workout_exercises we ON wes.workout_exercise_id = we.id
            JOIN workouts w ON we.workout_id = w.id
            JOIN exercises e ON we.exercise_id = e.id
            JOIN muscle_groups mg ON e.muscle_group_id = mg.id
            WHERE w.user_id = %s AND DATE(w.date) >= DATE_SUB(CURDATE(), INTERVAL 29 DAY)
            GROUP BY DATE(w.date), mg.id, mg.name
            ORDER BY DATE(w.date) DESC, mg.name;
            """
            
            cursor.execute(query, (user_id,))
            results = cursor.fetchall()
            
            # Generar las últimas 30 fechas
            dates = [(datetime.now().date() - timedelta(days=i)).strftime('%Y-%m-%d') for i in range(29, -1, -1)]
            muscle_groups = {}
            
            for row in results:
                muscle_group_id = row['muscle_group_id']
                if muscle_group_id not in muscle_groups:
                    muscle_groups[muscle_group_id] = {
                        "id": muscle_group_id,
                        "name": row['muscle_group'],
                        "sets": [0] * 30,  # Inicializa con 30 días
                        "bestSets": 0
                    }
                
                # Calcula el índice basado en la diferencia de días desde la fecha más reciente
                date_index = dates.index(row['date'].strftime('%Y-%m-%d'))
                sets = int(row['total_sets'])
                muscle_groups[muscle_group_id]["sets"][date_index] = sets
                muscle_groups[muscle_group_id]["bestSets"] = max(muscle_groups[muscle_group_id]["bestSets"], sets)
            
            formatted_results = {
                "dates": dates,
                "muscle_groups": list(muscle_groups.values())
            }
            
            return formatted_results
    except Exception as e:
        print(f"Error obteniendo sets mensuales por grupo muscular: {str(e)}")
        return None
    finally:
        if connection.is_connected():
            connection.close()

def get_sets_by_muscle_group_year(user_id: int):
    """
    Obtiene el número total de sets por grupo muscular en los últimos 12 meses para un usuario específico.
    Incluye meses sin entrenamiento.
    """
    try:
        connection = obtener_conexion()
        with connection.cursor(dictionary=True) as cursor:
            query = """
            SELECT 
                DATE_FORMAT(w.date, '%Y-%m') as date,
                mg.id as muscle_group_id,
                mg.name as muscle_group,
                COALESCE(SUM(wes.reps), 0) as total_sets
            FROM workouts w
            JOIN workout_exercises we ON w.id = we.workout_id
            JOIN workout_exercise_sets wes ON we.id = wes.workout_exercise_id
            JOIN exercises e ON we.exercise_id = e.id
            JOIN muscle_groups mg ON e.muscle_group_id = mg.id
            WHERE w.user_id = %s AND DATE(w.date) >= DATE_SUB(CURDATE(), INTERVAL 11 MONTH)
            GROUP BY DATE_FORMAT(w.date, '%Y-%m'), mg.id, mg.name
            ORDER BY DATE_FORMAT(w.date, '%Y-%m') DESC, mg.name;
            """
            
            cursor.execute(query, (user_id,))
            results = cursor.fetchall()
            
            # Generar los últimos 12 meses
            dates = [(datetime.now().replace(day=1) - timedelta(days=30*i)).strftime('%Y-%m') for i in range(11, -1, -1)]
            muscle_groups = {}
            
            for row in results:
                muscle_group_id = row['muscle_group_id']
                if muscle_group_id not in muscle_groups:
                    muscle_groups[muscle_group_id] = {
                        "id": muscle_group_id,
                        "name": row['muscle_group'],
                        "sets": [0] * 12,  # Inicializa con 12 meses
                        "bestSets": 0
                    }
                
                # Calcula el índice basado en la diferencia de meses desde el mes más reciente
                date_index = dates.index(row['date'])
                sets = int(row['total_sets'])
                muscle_groups[muscle_group_id]["sets"][date_index] = sets
                muscle_groups[muscle_group_id]["bestSets"] = max(muscle_groups[muscle_group_id]["bestSets"], sets)
            
            formatted_results = {
                "dates": dates,
                "muscle_groups": list(muscle_groups.values())
            }
            
            return formatted_results
    except Exception as e:
        print(f"Error obteniendo sets anuales por grupo muscular: {str(e)}")
        return None
    finally:
        if connection.is_connected():
            connection.close()

def get_sets_by_muscle_group_today(user_id: int):
    """
    Obtiene el número total de sets por grupo muscular para el día de hoy para un usuario específico.
    """
    try:
        connection = obtener_conexion()
        with connection.cursor(dictionary=True) as cursor:
            query = """
            SELECT 
                mg.id as muscle_group_id,
                mg.name as muscle_group,
                COALESCE(SUM(wes.reps), 0) as total_sets
            FROM workout_exercise_sets wes
            JOIN workout_exercises we ON wes.workout_exercise_id = we.id
            JOIN workouts w ON we.workout_id = w.id
            JOIN exercises e ON we.exercise_id = e.id
            JOIN muscle_groups mg ON e.muscle_group_id = mg.id
            WHERE w.user_id = %s AND DATE(w.date) = CURDATE() AND mg.id = 3
            GROUP BY mg.id, mg.name;
            """
            
            cursor.execute(query, (user_id,))
            results = cursor.fetchall()
            
            return results
    except Exception as e:
        print(f"Error obteniendo sets de hoy por grupo muscular: {str(e)}")
        return None
    finally:
        if connection.is_connected():
            connection.close()

def get_user_weights_week(user_id: int):
    """
    Obtiene los registros de peso para la última semana para un usuario específico.
    Incluye días sin registros.
    """
    try:
        connection = obtener_conexion()
        with connection.cursor(dictionary=True) as cursor:
            query = """
            SELECT 
                DATE(date) as date,
                weight
            FROM user_weight
            WHERE user_id = %s AND DATE(date) >= DATE_SUB(CURDATE(), INTERVAL 6 DAY)
            ORDER BY DATE(date) DESC;
            """
            
            cursor.execute(query, (user_id,))
            results = cursor.fetchall()
            
            # Generar las últimas 7 fechas
            dates = [(datetime.now().date() - timedelta(days=i)).strftime('%Y-%m-%d') for i in range(6, -1, -1)]
            weight_data = {date: None for date in dates}
            
            for row in results:
                date = row['date'].strftime('%Y-%m-%d')
                weight_data[date] = row['weight']
            
            formatted_results = [{"date": date, "weight": weight_data[date]} for date in dates]
            
            return formatted_results
    except Exception as e:
        print(f"Error obteniendo pesos semanales: {str(e)}")
        return None
    finally:
        if connection.is_connected():
            connection.close()

def get_user_weights_month(user_id: int):
    """
    Obtiene los registros de peso para el último mes para un usuario específico.
    Incluye días sin registros.
    """
    try:
        connection = obtener_conexion()
        with connection.cursor(dictionary=True) as cursor:
            query = """
            SELECT 
                DATE(date) as date,
                weight
            FROM user_weight
            WHERE user_id = %s AND DATE(date) >= DATE_SUB(CURDATE(), INTERVAL 29 DAY)
            ORDER BY DATE(date) DESC;
            """
            
            cursor.execute(query, (user_id,))
            results = cursor.fetchall()
            
            # Generar las últimas 30 fechas
            dates = [(datetime.now().date() - timedelta(days=i)).strftime('%Y-%m-%d') for i in range(29, -1, -1)]
            weight_data = {date: None for date in dates}
            
            for row in results:
                date = row['date'].strftime('%Y-%m-%d')
                weight_data[date] = row['weight']
            
            formatted_results = [{"date": date, "weight": weight_data[date]} for date in dates]
            
            return formatted_results
    except Exception as e:
        print(f"Error obteniendo pesos mensuales: {str(e)}")
        return None
    finally:
        if connection.is_connected():
            connection.close()

def get_user_monthly_weight_average(user_id: int):
    """
    Obtiene el promedio de peso por mes para un usuario específico en los últimos 12 meses.
    """
    try:
        connection = obtener_conexion()
        with connection.cursor(dictionary=True) as cursor:
            query = """
            SELECT 
                DATE_FORMAT(date, '%Y-%m') as month,
                AVG(weight) as average_weight
            FROM user_weight
            WHERE user_id = %s AND date >= DATE_SUB(CURDATE(), INTERVAL 11 MONTH)
            GROUP BY DATE_FORMAT(date, '%Y-%m')
            ORDER BY DATE_FORMAT(date, '%Y-%m') DESC;
            """
            
            cursor.execute(query, (user_id,))
            results = cursor.fetchall()
            
            # Generar los últimos 12 meses
            months = [(datetime.now().replace(day=1) - timedelta(days=30*i)).strftime('%Y-%m') for i in range(11, -1, -1)]
            weight_data = {month: None for month in months}
            
            for row in results:
                month = row['month']
                weight_data[month] = row['average_weight']
            
            formatted_results = {
                "months": months,
                "average_weights": [weight_data[month] for month in months]
            }
            
            return formatted_results
    except Exception as e:
        print(f"Error obteniendo promedio de peso mensual: {str(e)}")
        return None
    finally:
        if connection.is_connected():
            connection.close()

def update_user_profile_in_db(user_id: int, name: Optional[str], description: Optional[str], image_url: Optional[str]):
    """
    Actualiza el perfil de un usuario en la base de datos.
    
    Args:
        user_id (int): ID del usuario.
        name (Optional[str]): Nuevo nombre del usuario.
        description (Optional[str]): Nueva descripción del usuario.
        image_url (Optional[str]): Nueva URL de la imagen de perfil.
        
    Returns:
        bool: True si la actualización fue exitosa, False en caso contrario.
    """
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            # Construir la consulta SQL dinámicamente
            fields = []
            values = []

            if name is not None:
                fields.append("name = %s")
                values.append(name)
            if description is not None:
                fields.append("bio = %s")  # Mapea 'description' a 'bio'
                values.append(description)
            if image_url is not None:
                fields.append("image_url = %s")
                values.append(image_url)

            if not fields:
                return False  # No hay nada que actualizar

            query = f"UPDATE users SET {', '.join(fields)} WHERE id = %s"
            values.append(user_id)

            cursor.execute(query, values)
            conexion.commit()
            return cursor.rowcount > 0
    except Exception as e:
        conexion.rollback()
        print(f"Error al actualizar el perfil del usuario: {str(e)}")
        return False
    finally:
        conexion.close()

def register_user_weight_in_db(user_id: int, weight: float, record_date: date):
    """
    Registra el peso de un usuario en la base de datos.
    
    Args:
        user_id (int): ID del usuario.
        weight (float): Peso del usuario.
        record_date (date): Fecha del registro del peso.
        
    Returns:
        bool: True si el registro fue exitoso, False en caso contrario.
    """
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            query = """
            INSERT INTO user_weight (user_id, weight, date)
            VALUES (%s, %s, %s)
            """
            cursor.execute(query, (user_id, weight, record_date))
            conexion.commit()
            return cursor.rowcount > 0
    except Exception as e:
        conexion.rollback()
        print(f"Error al registrar el peso del usuario: {str(e)}")
        return False
    finally:
        conexion.close()

def add_recipe(name: str, description: str, image_url: str):
    """
    Agrega una nueva receta a la base de datos.
    
    Args:
        name (str): Nombre de la receta.
        description (str): Descripción de la receta.
        image_url (str): URL de la imagen de la receta.
        
    Returns:
        bool: True si la inserción fue exitosa, False en caso contrario.
    """
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            query = """
            INSERT INTO recipes (name, description, image_url)
            VALUES (%s, %s, %s)
            """
            cursor.execute(query, (name, description, image_url))
            conexion.commit()
            return cursor.rowcount > 0
    except Exception as e:
        conexion.rollback()
        print(f"Error al agregar la receta: {str(e)}")
        return False
    finally:
        conexion.close()

def delete_recipe_from_db(recipe_id: int):
    """
    Elimina una receta de la base de datos.
    
    Args:
        recipe_id (int): ID de la receta a eliminar.
        
    Returns:
        bool: True si la eliminación fue exitosa, False en caso contrario.
    """
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            query = "DELETE FROM recipes WHERE id = %s"
            cursor.execute(query, (recipe_id,))
            conexion.commit()
            return cursor.rowcount > 0
    except Exception as e:
        conexion.rollback()
        print(f"Error al eliminar la receta: {str(e)}")
        return False
    finally:
        conexion.close()

def update_recipe_in_db(recipe_id: int, name: Optional[str], description: Optional[str], image_url: Optional[str]):
    """
    Actualiza una receta en la base de datos.
    
    Args:
        recipe_id (int): ID de la receta.
        name (Optional[str]): Nuevo nombre de la receta.
        description (Optional[str]): Nueva descripción de la receta.
        image_url (Optional[str]): Nueva URL de la imagen de la receta.
        
    Returns:
        bool: True si la actualización fue exitosa, False en caso contrario.
    """
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            # Construir la consulta SQL dinámicamente
            fields = []
            values = []

            if name is not None:
                fields.append("name = %s")
                values.append(name)
            if description is not None:
                fields.append("description = %s")
                values.append(description)
            if image_url is not None:
                fields.append("image_url = %s")
                values.append(image_url)

            if not fields:
                return False  # No hay nada que actualizar

            query = f"UPDATE recipes SET {', '.join(fields)} WHERE id = %s"
            values.append(recipe_id)

            cursor.execute(query, values)
            conexion.commit()
            return cursor.rowcount > 0
    except Exception as e:
        conexion.rollback()
        print(f"Error al actualizar la receta: {str(e)}")
        return False
    finally:
        conexion.close()

def get_recipe_from_db(recipe_id: int):
    """
    Obtiene una receta de la base de datos por su ID.
    
    Args:
        recipe_id (int): ID de la receta.
        
    Returns:
        dict: Detalles de la receta o None si no se encuentra.
    """
    conexion = obtener_conexion()
    try:
        with conexion.cursor(dictionary=True) as cursor:
            query = "SELECT * FROM recipes WHERE id = %s"
            cursor.execute(query, (recipe_id,))
            recipe = cursor.fetchone()
            return recipe
    except Exception as e:
        print(f"Error al obtener la receta: {str(e)}")
        return None
    finally:
        conexion.close()

def get_all_recipes_from_db():
    """
    Obtiene el nombre y el ID de todas las recetas de la base de datos.
    
    Returns:
        list: Lista de diccionarios con el nombre y el ID de cada receta.
    """
    conexion = obtener_conexion()
    try:
        with conexion.cursor(dictionary=True) as cursor:
            query = "SELECT id, name FROM recipes"
            cursor.execute(query)
            recipes = cursor.fetchall()
            return recipes
    except Exception as e:
        print(f"Error al obtener las recetas: {str(e)}")
        return None
    finally:
        conexion.close()

def get_exercise_by_id(exercise_id: int):
    try:
        conexion = obtener_conexion()
        cursor = conexion.cursor(dictionary=True)

        query = """
        SELECT id, name, description, muscle_group_id, image_url
        FROM exercises
        WHERE id = %s
        """
        cursor.execute(query, (exercise_id,))
        exercise = cursor.fetchone()

        return exercise

    except Exception as e:
        print(f"Error getting exercise: {str(e)}")
        raise HTTPException(status_code=500, detail="An error occurred while retrieving the exercise")
    finally:
        if 'conexion' in locals() and conexion.is_connected():
            cursor.close()
            conexion.close()

def update_exercise_in_db(exercise_id: int, name: Optional[str], description: Optional[str], muscle_group_id: Optional[int], image_url: Optional[str]):
    """
    Actualiza un ejercicio en la base de datos.

    Args:
        exercise_id (int): ID del ejercicio.
        name (Optional[str]): Nuevo nombre del ejercicio.
        description (Optional[str]): Nueva descripción del ejercicio.
        muscle_group_id (Optional[int]): Nuevo ID del grupo muscular.
        image_url (Optional[str]): Nueva URL de la imagen del ejercicio.
        
    Returns:
        bool: True si la actualización fue exitosa, False en caso contrario.
    """
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            # Construir la consulta SQL dinámicamente
            fields = []
            values = []

            if name is not None:
                fields.append("name = %s")
                values.append(name)
            if description is not None:
                fields.append("description = %s")
                values.append(description)
            if muscle_group_id is not None:
                fields.append("muscle_group_id = %s")
                values.append(int(muscle_group_id))  # Convertir a entero
            if image_url is not None:
                fields.append("image_url = %s")
                values.append(image_url)

            if not fields:
                return False  # No hay nada que actualizar

            query = f"UPDATE exercises SET {', '.join(fields)} WHERE id = %s"
            values.append(exercise_id)

            cursor.execute(query, values)
            conexion.commit()
            return cursor.rowcount > 0
    except Exception as e:
        conexion.rollback()
        print(f"Error al actualizar el ejercicio: {str(e)}")
        return False
    finally:
        conexion.close()

def delete_exercise_from_db(exercise_id: int):
    """
    Elimina un ejercicio de la base de datos.

    Args:
        exercise_id (int): ID del ejercicio a eliminar.
        
    Returns:
        bool: True si la eliminación fue exitosa, False en caso contrario.
    """
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            # Eliminar dependencias en routine_exercises
            cursor.execute("DELETE FROM routine_exercises WHERE exercise_id = %s", (exercise_id,))
            
            # Eliminar el ejercicio
            cursor.execute("DELETE FROM exercises WHERE id = %s", (exercise_id,))
            conexion.commit()
            return cursor.rowcount > 0
    except Exception as e:
        conexion.rollback()
        print(f"Error al eliminar el ejercicio: {str(e)}")
        return False
    finally:
        conexion.close()