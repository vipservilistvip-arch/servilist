import os
import re
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, request, send_from_directory, session
from flask_cors import CORS
from werkzeug.security import check_password_hash, generate_password_hash

# Obter o caminho absoluto da pasta do projeto
basedir = os.path.abspath(os.path.dirname(__file__))
dist_folder = os.path.join(basedir, 'dist')
db_path = Path(basedir) / 'servlist.db'

app = Flask(__name__, static_folder=dist_folder)

# Configuracao de sessao
app.config['SECRET_KEY'] = os.getenv('SERVLIST_SECRET_KEY', 'change-this-secret-in-production')
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.getenv('SESSION_COOKIE_SECURE', 'false').lower() == 'true'

# CORS para desenvolvimento (Vite) e mesmo host em producao
allowed_origins = os.getenv('SERVLIST_ALLOWED_ORIGINS', 'http://localhost:5173,http://127.0.0.1:5173').split(',')
CORS(app, supports_credentials=True, origins=[origin.strip() for origin in allowed_origins if origin.strip()])

EMAIL_REGEX = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with get_db_connection() as conn:
        conn.execute(
            '''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            '''
        )
        conn.execute(
            '''
            CREATE TABLE IF NOT EXISTS servers (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                client TEXT NOT NULL,
                ip TEXT NOT NULL,
                port TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                reference_point TEXT NOT NULL,
                mikrotik_user TEXT NOT NULL,
                mikrotik_password TEXT NOT NULL,
                os TEXT NOT NULL,
                hardware TEXT NOT NULL,
                status TEXT NOT NULL,
                backup_status TEXT NOT NULL,
                last_backup TEXT NOT NULL,
                notes TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
            '''
        )
        conn.commit()


def normalize_email(email: str) -> str:
    return email.strip().lower()


def find_user_by_email(email: str) -> sqlite3.Row | None:
    with get_db_connection() as conn:
        return conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()


def find_user_by_id(user_id: int) -> sqlite3.Row | None:
    with get_db_connection() as conn:
        return conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()


def current_user() -> sqlite3.Row | None:
    user_id = session.get('user_id')
    if not user_id:
        return None

    return find_user_by_id(user_id)


def user_response_payload(user: sqlite3.Row) -> dict[str, Any]:
    return {
        'id': user['id'],
        'name': user['name'],
        'email': user['email'],
        'createdAt': user['created_at'],
    }


def require_auth() -> tuple[sqlite3.Row | None, tuple[Any, int] | None]:
    user = current_user()
    if not user:
        return None, (jsonify({'error': 'Nao autenticado.'}), 401)
    return user, None


def server_row_to_payload(server: sqlite3.Row) -> dict[str, Any]:
    return {
        'id': server['id'],
        'name': server['name'],
        'client': server['client'],
        'ip': server['ip'],
        'port': server['port'],
        'endpoint': server['endpoint'],
        'referencePoint': server['reference_point'],
        'mikrotikUser': server['mikrotik_user'],
        'mikrotikPassword': server['mikrotik_password'],
        'os': server['os'],
        'hardware': server['hardware'],
        'status': server['status'],
        'backupStatus': server['backup_status'],
        'lastBackup': server['last_backup'],
        'notes': server['notes'],
    }


def validate_server_payload(payload: dict[str, Any]) -> tuple[dict[str, str], str | None]:
    status_value = str(payload.get('status', 'online')).strip().lower()
    backup_status_value = str(payload.get('backupStatus', 'pending')).strip().lower()

    if status_value not in {'online', 'offline', 'maintenance'}:
        return {}, 'Status invalido.'
    if backup_status_value not in {'success', 'failed', 'pending'}:
        return {}, 'Status de backup invalido.'

    normalized = {
        'id': str(payload.get('id', '')).strip(),
        'name': str(payload.get('name', '')).strip(),
        'client': str(payload.get('client', '')).strip(),
        'ip': str(payload.get('ip', 'N/A')).strip() or 'N/A',
        'port': str(payload.get('port', '80')).strip() or '80',
        'endpoint': str(payload.get('endpoint', 'N/A')).strip() or 'N/A',
        'referencePoint': str(payload.get('referencePoint', '')).strip(),
        'mikrotikUser': str(payload.get('mikrotikUser', '')).strip(),
        'mikrotikPassword': str(payload.get('mikrotikPassword', '')).strip(),
        'os': str(payload.get('os', 'N/A')).strip() or 'N/A',
        'hardware': str(payload.get('hardware', 'N/A')).strip() or 'N/A',
        'status': status_value,
        'backupStatus': backup_status_value,
        'lastBackup': str(payload.get('lastBackup', datetime.utcnow().isoformat())).strip() or datetime.utcnow().isoformat(),
        'notes': str(payload.get('notes', '')).strip(),
    }

    if not normalized['id']:
        return {}, 'ID do servidor e obrigatorio.'
    if not normalized['name'] or not normalized['client']:
        return {}, 'Nome e cliente sao obrigatorios.'

    return normalized, None


@app.get('/api/health')
def health_check():
    return jsonify({'status': 'ok'})


@app.post('/api/auth/register')
def register_user():
    payload = request.get_json(silent=True) or {}

    name = str(payload.get('name', '')).strip()
    email = normalize_email(str(payload.get('email', '')))
    password = str(payload.get('password', ''))

    if not name:
        return jsonify({'error': 'Nome e obrigatorio.'}), 400

    if not EMAIL_REGEX.match(email):
        return jsonify({'error': 'Email invalido.'}), 400

    if len(password) < 8:
        return jsonify({'error': 'A senha deve ter pelo menos 8 caracteres.'}), 400

    if find_user_by_email(email):
        return jsonify({'error': 'Este email ja esta cadastrado.'}), 409

    password_hash = generate_password_hash(password)
    created_at = datetime.utcnow().isoformat()

    with get_db_connection() as conn:
        cursor = conn.execute(
            'INSERT INTO users (name, email, password_hash, created_at) VALUES (?, ?, ?, ?)',
            (name, email, password_hash, created_at),
        )
        conn.commit()
        user_id = cursor.lastrowid

    session.clear()
    session['user_id'] = user_id

    user = find_user_by_id(user_id)
    if not user:
        return jsonify({'error': 'Falha ao criar usuario.'}), 500

    return jsonify({'user': user_response_payload(user)}), 201


@app.post('/api/auth/login')
def login_user():
    payload = request.get_json(silent=True) or {}

    email = normalize_email(str(payload.get('email', '')))
    password = str(payload.get('password', ''))

    user = find_user_by_email(email)
    if not user or not check_password_hash(user['password_hash'], password):
        return jsonify({'error': 'Credenciais invalidas.'}), 401

    session.clear()
    session['user_id'] = user['id']

    return jsonify({'user': user_response_payload(user)})


@app.get('/api/auth/me')
def auth_me():
    user = current_user()
    if not user:
        return jsonify({'user': None}), 200

    return jsonify({'user': user_response_payload(user)})


@app.post('/api/auth/logout')
def logout_user():
    session.clear()
    return jsonify({'ok': True})


@app.get('/api/servers')
def list_servers():
    user, auth_error = require_auth()
    if auth_error:
        return auth_error

    with get_db_connection() as conn:
        rows = conn.execute(
            '''
            SELECT * FROM servers
            WHERE user_id = ?
            ORDER BY created_at DESC
            ''',
            (user['id'],),
        ).fetchall()

    return jsonify({'servers': [server_row_to_payload(row) for row in rows]})


@app.post('/api/servers')
def create_server():
    user, auth_error = require_auth()
    if auth_error:
        return auth_error

    payload = request.get_json(silent=True) or {}
    normalized, error = validate_server_payload(payload)
    if error:
        return jsonify({'error': error}), 400

    now = datetime.utcnow().isoformat()
    with get_db_connection() as conn:
        existing = conn.execute(
            'SELECT id FROM servers WHERE id = ? AND user_id = ?',
            (normalized['id'], user['id']),
        ).fetchone()
        if existing:
            return jsonify({'error': 'ID de servidor ja cadastrado.'}), 409

        conn.execute(
            '''
            INSERT INTO servers (
                id, user_id, name, client, ip, port, endpoint,
                reference_point, mikrotik_user, mikrotik_password, os, hardware,
                status, backup_status, last_backup, notes, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''',
            (
                normalized['id'],
                user['id'],
                normalized['name'],
                normalized['client'],
                normalized['ip'],
                normalized['port'],
                normalized['endpoint'],
                normalized['referencePoint'],
                normalized['mikrotikUser'],
                normalized['mikrotikPassword'],
                normalized['os'],
                normalized['hardware'],
                normalized['status'],
                normalized['backupStatus'],
                normalized['lastBackup'],
                normalized['notes'],
                now,
                now,
            ),
        )
        conn.commit()

        row = conn.execute(
            'SELECT * FROM servers WHERE id = ? AND user_id = ?',
            (normalized['id'], user['id']),
        ).fetchone()

    if not row:
        return jsonify({'error': 'Falha ao criar servidor.'}), 500

    return jsonify({'server': server_row_to_payload(row)}), 201


@app.put('/api/servers/<server_id>')
def update_server(server_id: str):
    user, auth_error = require_auth()
    if auth_error:
        return auth_error

    payload = request.get_json(silent=True) or {}
    payload['id'] = server_id
    normalized, error = validate_server_payload(payload)
    if error:
        return jsonify({'error': error}), 400

    with get_db_connection() as conn:
        existing = conn.execute(
            'SELECT id FROM servers WHERE id = ? AND user_id = ?',
            (server_id, user['id']),
        ).fetchone()
        if not existing:
            return jsonify({'error': 'Servidor nao encontrado.'}), 404

        conn.execute(
            '''
            UPDATE servers
            SET
                name = ?,
                client = ?,
                ip = ?,
                port = ?,
                endpoint = ?,
                reference_point = ?,
                mikrotik_user = ?,
                mikrotik_password = ?,
                os = ?,
                hardware = ?,
                status = ?,
                backup_status = ?,
                last_backup = ?,
                notes = ?,
                updated_at = ?
            WHERE id = ? AND user_id = ?
            ''',
            (
                normalized['name'],
                normalized['client'],
                normalized['ip'],
                normalized['port'],
                normalized['endpoint'],
                normalized['referencePoint'],
                normalized['mikrotikUser'],
                normalized['mikrotikPassword'],
                normalized['os'],
                normalized['hardware'],
                normalized['status'],
                normalized['backupStatus'],
                normalized['lastBackup'],
                normalized['notes'],
                datetime.utcnow().isoformat(),
                server_id,
                user['id'],
            ),
        )
        conn.commit()

        row = conn.execute(
            'SELECT * FROM servers WHERE id = ? AND user_id = ?',
            (server_id, user['id']),
        ).fetchone()

    if not row:
        return jsonify({'error': 'Falha ao atualizar servidor.'}), 500

    return jsonify({'server': server_row_to_payload(row)})


@app.delete('/api/servers/<server_id>')
def delete_server(server_id: str):
    user, auth_error = require_auth()
    if auth_error:
        return auth_error

    with get_db_connection() as conn:
        cursor = conn.execute(
            'DELETE FROM servers WHERE id = ? AND user_id = ?',
            (server_id, user['id']),
        )
        conn.commit()

    if cursor.rowcount == 0:
        return jsonify({'error': 'Servidor nao encontrado.'}), 404

    return jsonify({'ok': True})


# Serve React App
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve(path: str):
    # Tenta servir o arquivo solicitado na pasta dist
    requested_file = os.path.join(app.static_folder, path)
    if path != '' and os.path.exists(requested_file):
        return send_from_directory(app.static_folder, path)

    # Se nao encontrar (rotas do React), serve o index.html
    return send_from_directory(app.static_folder, 'index.html')


init_db()

if __name__ == '__main__':
    app.run(use_reloader=True, port=5000, threaded=True)
