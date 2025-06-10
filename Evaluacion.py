from flask import Flask, request, jsonify, g
import sqlite3
import jwt
from functools import wraps
import os
import bcrypt
from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['DEBUG'] = os.getenv('DEBUG') == 'True'

TOKEN_EXPIRATION_MINUTES = 5

# -- Base de datos y tablas --


def init_db():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    # Tabla usuarios
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            email TEXT UNIQUE,
            birthdate DATE,
            status INTEGER DEFAULT 1,
            secret_question TEXT,
            secret_answer TEXT,
            role_id INTEGER,
            FOREIGN KEY(role_id) REFERENCES roles(id)
        )
    """)

    # Tabla roles
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS roles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE
        )
    """)

    # Tabla permisos
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE
        )
    """)

    # Relación roles y permisos
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS role_permissions (
            role_id INTEGER,
            permission_id INTEGER,
            PRIMARY KEY(role_id, permission_id),
            FOREIGN KEY(role_id) REFERENCES roles(id),
            FOREIGN KEY(permission_id) REFERENCES permissions(id)
        )
    """)

    # Insertar roles (si no existen)
    roles = ['superadmin', 'admin', 'common_user', 'seller']
    for role in roles:
        cursor.execute(
            "INSERT OR IGNORE INTO roles (name) VALUES (?)", (role,))

    # Insertar permisos
    permissions = [
        'get_user', 'create_user', 'update_user', 'delete_user',
        'create_role', 'get_role', 'update_role', 'delete_role',
        'create_permission', 'get_permission', 'update_permission', 'delete_permission',
        'create_product', 'get_product', 'update_product', 'delete_product'
    ]
    for perm in permissions:
        cursor.execute(
            "INSERT OR IGNORE INTO permissions (name) VALUES (?)", (perm,))

    # Asignar permisos a roles (vaciar y luego asignar)
    cursor.execute("DELETE FROM role_permissions")

    # Obtener ids de roles y permisos para asignar
    cursor.execute("SELECT id, name FROM roles")
    roles_db = {name: rid for rid, name in cursor.fetchall()}

    cursor.execute("SELECT id, name FROM permissions")
    perms_db = {name: pid for pid, name in cursor.fetchall()}

    # Asignaciones
    role_perms_map = {
        'superadmin': permissions,
        'admin': ['get_user', 'create_user', 'update_user', 'delete_user'],
        'common_user': ['get_user', 'get_product', 'update_user'],
        'seller': ['create_product', 'get_product', 'update_product', 'delete_product']
    }

    for role_name, perms_list in role_perms_map.items():
        rid = roles_db[role_name]
        for perm_name in perms_list:
            pid = perms_db[perm_name]
            cursor.execute(
                "INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)", (rid, pid))

   # Insertar usuario admin si no existe
    cursor.execute("SELECT id FROM users WHERE username = 'admin'")
    admin_exists = cursor.fetchone()

    superadmin_id = roles_db['superadmin']

    if not admin_exists:
        hashed_password = bcrypt.hashpw('abcd4321'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        cursor.execute("""
            INSERT INTO users (username, password, email, birthdate, secret_question, secret_answer, role_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            'admin',
            hashed_password,
            'correo@correo.com',
            '1998-10-28',
            '¿Cuál es tu color favorito?',
            'Negro',
            superadmin_id
        ))
        conn.commit()
        conn.close()



def get_db_connection():
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    return conn

# -- Autenticación y autorización --


def generate_token(user_id, role_id):
    payload = {
        'user_id': user_id,
        'role_id': role_id,
        'exp': datetime.now(timezone.utc) + timedelta(minutes=TOKEN_EXPIRATION_MINUTES)
    }
    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
    return token


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header[7:]
        if not token:
            return jsonify({'error': 'Token es requerido'}), 401

        try:
            data = jwt.decode(
                token, app.config['SECRET_KEY'], algorithms=['HS256'])
            g.user_id = data['user_id']
            g.role_id = data['role_id']
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expirado'}), 401
        except Exception as e:
            return jsonify({'error': 'Token inválido'}), 401

        return f(*args, **kwargs)
    return decorated


def permission_required(permission_name):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            conn = get_db_connection()
            cursor = conn.cursor()
            # Obtener role_id y verificar permiso
            cursor.execute("""
                SELECT p.name FROM permissions p
                JOIN role_permissions rp ON p.id = rp.permission_id
                WHERE rp.role_id = ? AND p.name = ?
            """, (g.role_id, permission_name))
            perm = cursor.fetchone()
            conn.close()
            if not perm:
                return jsonify({'error': f'Permiso "{permission_name}" requerido'}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator

# -- Rutas de autenticación --


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    required_fields = ['username', 'password',
                       'email', 'birthdate', 'secret_answer']
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Faltan campos requeridos"}), 400

    try:
        datetime.strptime(data['birthdate'], '%Y-%m-%d').date()
    except ValueError:
        return jsonify({"error": "Formato de fecha inválido. Use YYYY-MM-DD"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    # Asignar rol common_user por defecto
    cursor.execute("SELECT id FROM roles WHERE name='common_user'")
    common_user_role = cursor.fetchone()
    role_id = common_user_role['id'] if common_user_role else None

    # Hashear la contraseña antes de guardarla
    hashed_password = bcrypt.hashpw(data['password'].encode(
        'utf-8'), bcrypt.gensalt()).decode('utf-8')

    try:
        cursor.execute("""
            INSERT INTO users (
                username, password, email, birthdate, status,
                secret_question, secret_answer, role_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            data['username'],
            hashed_password,
            data['email'],
            data['birthdate'],
            1,
            '¿Cuál es tu color favorito?',
            data['secret_answer'],
            role_id
        ))
        conn.commit()
        return jsonify({"message": "Usuario registrado exitosamente"}), 201
    except sqlite3.IntegrityError as e:
        return jsonify({"error": "Usuario o email ya existen"}), 400
    finally:
        conn.close()


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({"error": "Usuario y password son requeridos"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, password, role_id FROM users WHERE username = ? AND status = 1
    """, (data['username'],))

    user = cursor.fetchone()
    conn.close()

    # Validar contraseña con bcrypt
    if not user or not bcrypt.checkpw(data['password'].encode('utf-8'), user['password'].encode('utf-8')):
        return jsonify({"error": "Credenciales inválidas"}), 401

    token = generate_token(user['id'], user['role_id'])
    return jsonify({'token': token})

# -- CRUD usuarios con permisos --


@app.route('/users', methods=['GET'])
@token_required
@permission_required('get_user')
def get_all_users():
    user_id = g.user_id
    role_id = g.role_id

    conn = get_db_connection()
    cursor = conn.cursor()

    if role_id == 1:  # superadmin o admin, según tu base
        cursor.execute(
            "SELECT id, username, email, birthdate, status, role_id FROM users WHERE status = 1")
        users = cursor.fetchall()
    else:
        # En SQLite el placeholder es ?, no %s
        cursor.execute(
            "SELECT id, username, email, birthdate, status, role_id FROM users WHERE status = 1 AND id = ?", (user_id,))
        users = cursor.fetchall()

    conn.close()

    users_list = [dict(user) for user in users]
    return jsonify({"users": users_list})


@app.route('/user/<int:user_id>', methods=['GET'])
@token_required
@permission_required('get_user')
def get_user_by_id(user_id):
    # common_user solo puede ver su propio usuario
    if g.role_id is not None:
        conn = get_db_connection()
        cursor = conn.cursor()
        # Obtener rol del usuario actual
        cursor.execute("SELECT name FROM roles WHERE id=?", (g.role_id,))
        role_name = cursor.fetchone()['name']
        conn.close()
        if role_name == 'common_user' and g.user_id != user_id:
            return jsonify({"error": "No tienes permiso para ver otros usuarios"}), 403

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, username, email, birthdate, status, role_id FROM users WHERE id = ? AND status = 1
    """, (user_id,))
    user = cursor.fetchone()
    conn.close()

    if user:
        return jsonify(dict(user))
    else:
        return jsonify({"error": "Usuario no encontrado o inactivo"}), 404


@app.route('/user/<int:user_id>', methods=['PUT'])
@token_required
@permission_required('update_user')
def update_user(user_id):
    data = request.get_json()
    conn = get_db_connection()
    cursor = conn.cursor()

    # Verificar si usuario existe
    cursor.execute(
        "SELECT id, role_id FROM users WHERE id = ? AND status = 1", (user_id,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        return jsonify({"error": "Usuario no encontrado o inactivo"}), 404

    # common_user solo puede actualizar su propio usuario
    cursor.execute("SELECT name FROM roles WHERE id=?", (g.role_id,))
    role_name = cursor.fetchone()['name']
    if role_name == 'common_user' and g.user_id != user_id:
        conn.close()
        return jsonify({"error": "No tienes permiso para actualizar otros usuarios"}), 403

    update_fields = []
    params = []

    for field in ['username', 'email', 'birthdate', 'status']:
        if field in data:
            update_fields.append(f"{field} = ?")
            params.append(data[field])

    if not update_fields:
        conn.close()
        return jsonify({"error": "No hay campos para actualizar"}), 400

    params.append(user_id)
    query = f"UPDATE users SET {', '.join(update_fields)} WHERE id = ? "

    try:
        cursor.execute(query, params)
        conn.commit()
        return jsonify({"message": "Usuario actualizado exitosamente"})
    except sqlite3.IntegrityError:
        return jsonify({"error": "Error de integridad (usuario/email ya existe)"}), 400
    finally:
        conn.close()


@app.route('/user/<int:user_id>', methods=['DELETE'])
@token_required
@permission_required('delete_user')
def delete_user(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "UPDATE users SET status = 0 WHERE id = ? AND status = 1", (user_id,))
    conn.commit()
    affected_rows = conn.total_changes
    conn.close()

    if affected_rows > 0:
        return jsonify({"message": "Usuario desactivado exitosamente"})
    else:
        return jsonify({"error": "Usuario no encontrado o ya inactivo"}), 404

# -- Gestión roles --


@app.route('/roles', methods=['GET'])
@token_required
@permission_required('get_role')
def get_roles():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, name FROM roles")
    roles = cursor.fetchall()
    conn.close()
    roles_list = [dict(role) for role in roles]
    return jsonify({"roles": roles_list})


@app.route('/role', methods=['POST'])
@token_required
@permission_required('create_role')
def create_role():
    data = request.get_json()
    if 'name' not in data:
        return jsonify({"error": "Falta nombre de rol"}), 400
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO roles (name) VALUES (?)", (data['name'],))
        conn.commit()
        return jsonify({"message": "Rol creado exitosamente"})
    except sqlite3.IntegrityError:
        return jsonify({"error": "Rol ya existe"}), 400
    finally:
        conn.close()


@app.route('/role/<int:role_id>', methods=['PUT'])
@token_required
@permission_required('update_role')
def update_role(role_id):
    data = request.get_json()
    if 'name' not in data:
        return jsonify({"error": "Falta nombre de rol"}), 400
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM roles WHERE id = ?", (role_id,))
    if not cursor.fetchone():
        conn.close()
        return jsonify({"error": "Rol no encontrado"}), 404
    try:
        cursor.execute("UPDATE roles SET name = ? WHERE id = ?",
                       (data['name'], role_id))
        conn.commit()
        return jsonify({"message": "Rol actualizado exitosamente"})
    except sqlite3.IntegrityError:
        return jsonify({"error": "Rol ya existe"}), 400
    finally:
        conn.close()


@app.route('/role/<int:role_id>', methods=['DELETE'])
@token_required
@permission_required('delete_role')
def delete_role(role_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM roles WHERE id = ?", (role_id,))
    conn.commit()
    affected = conn.total_changes
    conn.close()
    if affected > 0:
        return jsonify({"message": "Rol eliminado exitosamente"})
    else:
        return jsonify({"error": "Rol no encontrado"}), 404

# -- Gestión permisos --


@app.route('/permissions', methods=['GET'])
@token_required
@permission_required('get_permission')
def get_permissions():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, name FROM permissions")
    permissions = cursor.fetchall()
    conn.close()
    permissions_list = [dict(perm) for perm in permissions]
    return jsonify({"permissions": permissions_list})


@app.route('/permission', methods=['POST'])
@token_required
@permission_required('create_permission')
def create_permission():
    data = request.get_json()
    if 'name' not in data:
        return jsonify({"error": "Falta nombre de permiso"}), 400
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO permissions (name) VALUES (?)", (data['name'],))
        conn.commit()
        return jsonify({"message": "Permiso creado exitosamente"})
    except sqlite3.IntegrityError:
        return jsonify({"error": "Permiso ya existe"}), 400
    finally:
        conn.close()


@permission_required('update_permission')
def update_permission(permission_id):
    data = request.get_json()
    if not data or 'name' not in data:
        return jsonify({"error": "Falta nombre del permiso"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM permissions WHERE id = ?", (permission_id,))
    role = cursor.fetchone()
    if not role:
        conn.close()
        return jsonify({"error": "Permiso no encontrado"}), 404

    try:
        cursor.execute("UPDATE permissions SET name = ? WHERE id = ?",
                       (data['name'], permission_id))
        conn.commit()
        return jsonify({"message": "permiso actualizado exitosamente"})
    except sqlite3.IntegrityError:
        return jsonify({"error": "El nombre del permiso ya existe"}), 400
    finally:
        conn.close()


@app.route('/permission/<int:permission_id>', methods=['DELETE'])
@token_required
@permission_required('delete_permission')
def delete_permission(permission_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    # Opcional: verificar que no haya usuarios asignados a este rol antes de eliminar

    cursor.execute("DELETE FROM permissions WHERE id = ?", (permission_id,))
    conn.commit()
    affected_rows = conn.total_changes
    conn.close()

    if affected_rows > 0:
        return jsonify({"message": "permiso eliminado exitosamente"})
    else:
        return jsonify({"error": "permiso no encontrado"}), 404


if __name__ == '__main__':
    init_db()
    app.run(debug=True)
