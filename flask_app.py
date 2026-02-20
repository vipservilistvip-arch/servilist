import os
import re
import sqlite3
import smtplib
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email import encoders

from flask import Flask, jsonify, request, send_from_directory, session, send_file
from flask_cors import CORS
from flask_apscheduler import APScheduler
from werkzeug.security import check_password_hash, generate_password_hash

# Obter o caminho absoluto da pasta do projeto
basedir = os.path.abspath(os.path.dirname(__file__))
dist_folder = os.path.join(basedir, 'dist')

# Configuração de persistência do banco de dados
if os.environ.get('PYTHONANYWHERE_DOMAIN'):
    # No PythonAnywhere, salva fora da pasta do projeto para evitar sobrescrita pelo Git
    db_path = Path('/home/servilistvip2026/servlist.db')
else:
    # Localmente, mantém na pasta do projeto
    db_path = Path(basedir) / 'servlist.db'

import logging
import traceback

app = Flask(__name__, static_folder=dist_folder)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@app.errorhandler(Exception)
def handle_exception(e):
    # Pass through HTTP errors
    if isinstance(e,  Exception) and hasattr(e, 'code'):
        return e
    
    # Log the full traceback
    logger.error(f"Unhandled Exception: {str(e)}")
    logger.error(traceback.format_exc())
    
    return jsonify({'error': 'Internal Server Error', 'details': str(e)}), 500

# Scheduler configuration
app.config['SCHEDULER_API_ENABLED'] = True
scheduler = APScheduler()
scheduler.init_app(app)
scheduler.start()

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
        conn.execute(
            '''
            CREATE TABLE IF NOT EXISTS contract_points (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                equipment_user TEXT NOT NULL,
                equipment_password TEXT NOT NULL,
                provider_name TEXT NOT NULL,
                provider_contact TEXT NOT NULL,
                provider_holder TEXT NOT NULL,
                provider_cpf_cnpj TEXT NOT NULL,
                provider_city TEXT NOT NULL,
                notes TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
            '''
        )
        conn.execute(
            '''
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
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


def contract_point_row_to_payload(row: sqlite3.Row) -> dict[str, Any]:
    return {
        'id': row['id'],
        'name': row['name'],
        'equipmentUser': row['equipment_user'],
        'equipmentPassword': row['equipment_password'],
        'providerName': row['provider_name'],
        'providerContact': row['provider_contact'],
        'providerHolder': row['provider_holder'],
        'providerCpfCnpj': row['provider_cpf_cnpj'],
        'providerCity': row['provider_city'],
        'notes': row['notes'],
    }


def validate_contract_point_payload(payload: dict[str, Any]) -> tuple[dict[str, str], str | None]:
    normalized = {
        'id': str(payload.get('id', '')).strip(),
        'name': str(payload.get('name', '')).strip(),
        'equipmentUser': str(payload.get('equipmentUser', '')).strip(),
        'equipmentPassword': str(payload.get('equipmentPassword', '')).strip(),
        'providerName': str(payload.get('providerName', '')).strip(),
        'providerContact': str(payload.get('providerContact', '')).strip(),
        'providerHolder': str(payload.get('providerHolder', '')).strip(),
        'providerCpfCnpj': str(payload.get('providerCpfCnpj', '')).strip(),
        'providerCity': str(payload.get('providerCity', '')).strip(),
        'notes': str(payload.get('notes', '')).strip(),
    }

    if not normalized['id']:
        return {}, 'ID do ponto de contratacao e obrigatorio.'
    if not normalized['name']:
        return {}, 'Nome do ponto de contratacao e obrigatorio.'

    return normalized, None


@app.get('/api/contract-points')
def list_contract_points():
    user, auth_error = require_auth()
    if auth_error:
        return auth_error

    with get_db_connection() as conn:
        rows = conn.execute(
            '''
            SELECT * FROM contract_points
            WHERE user_id = ?
            ORDER BY created_at DESC
            ''',
            (user['id'],),
        ).fetchall()

    return jsonify({'contractPoints': [contract_point_row_to_payload(row) for row in rows]})


@app.post('/api/contract-points')
def create_contract_point():
    user, auth_error = require_auth()
    if auth_error:
        return auth_error

    payload = request.get_json(silent=True) or {}
    normalized, error = validate_contract_point_payload(payload)
    if error:
        return jsonify({'error': error}), 400

    now = datetime.utcnow().isoformat()
    with get_db_connection() as conn:
        existing = conn.execute(
            'SELECT id FROM contract_points WHERE id = ? AND user_id = ?',
            (normalized['id'], user['id']),
        ).fetchone()
        if existing:
            return jsonify({'error': 'ID de ponto de contratacao ja cadastrado.'}), 409

        conn.execute(
            '''
            INSERT INTO contract_points (
                id, user_id, name, equipment_user, equipment_password,
                provider_name, provider_contact, provider_holder,
                provider_cpf_cnpj, provider_city, notes, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''',
            (
                normalized['id'],
                user['id'],
                normalized['name'],
                normalized['equipmentUser'],
                normalized['equipmentPassword'],
                normalized['providerName'],
                normalized['providerContact'],
                normalized['providerHolder'],
                normalized['providerCpfCnpj'],
                normalized['providerCity'],
                normalized['notes'],
                now,
                now,
            ),
        )
        conn.commit()

        row = conn.execute(
            'SELECT * FROM contract_points WHERE id = ? AND user_id = ?',
            (normalized['id'], user['id']),
        ).fetchone()

    if not row:
        return jsonify({'error': 'Falha ao criar ponto de contratacao.'}), 500

    return jsonify({'contractPoint': contract_point_row_to_payload(row)}), 201


@app.put('/api/contract-points/<point_id>')
def update_contract_point(point_id: str):
    user, auth_error = require_auth()
    if auth_error:
        return auth_error

    payload = request.get_json(silent=True) or {}
    payload['id'] = point_id
    normalized, error = validate_contract_point_payload(payload)
    if error:
        return jsonify({'error': error}), 400

    with get_db_connection() as conn:
        existing = conn.execute(
            'SELECT id FROM contract_points WHERE id = ? AND user_id = ?',
            (point_id, user['id']),
        ).fetchone()
        if not existing:
            return jsonify({'error': 'Ponto de contratacao nao encontrado.'}), 404

        conn.execute(
            '''
            UPDATE contract_points
            SET
                name = ?,
                equipment_user = ?,
                equipment_password = ?,
                provider_name = ?,
                provider_contact = ?,
                provider_holder = ?,
                provider_cpf_cnpj = ?,
                provider_city = ?,
                notes = ?,
                updated_at = ?
            WHERE id = ? AND user_id = ?
            ''',
            (
                normalized['name'],
                normalized['equipmentUser'],
                normalized['equipmentPassword'],
                normalized['providerName'],
                normalized['providerContact'],
                normalized['providerHolder'],
                normalized['providerCpfCnpj'],
                normalized['providerCity'],
                normalized['notes'],
                datetime.utcnow().isoformat(),
                point_id,
                user['id'],
            ),
        )
        conn.commit()

        row = conn.execute(
            'SELECT * FROM contract_points WHERE id = ? AND user_id = ?',
            (point_id, user['id']),
        ).fetchone()

    if not row:
        return jsonify({'error': 'Falha ao atualizar ponto de contratacao.'}), 500

    return jsonify({'contractPoint': contract_point_row_to_payload(row)})


@app.delete('/api/contract-points/<point_id>')
def delete_contract_point(point_id: str):
    user, auth_error = require_auth()
    if auth_error:
        return auth_error

    with get_db_connection() as conn:
        cursor = conn.execute(
            'DELETE FROM contract_points WHERE id = ? AND user_id = ?',
            (point_id, user['id']),
        )
        conn.commit()

    if cursor.rowcount == 0:
        return jsonify({'error': 'Ponto de contratacao nao encontrado.'}), 404

    return jsonify({'ok': True})



# --- Backup System ---

def get_setting(key: str, default: str = '') -> str:
    with get_db_connection() as conn:
        row = conn.execute('SELECT value FROM settings WHERE key = ?', (key,)).fetchone()
        return row['value'] if row else default


def set_setting(key: str, value: str) -> None:
    with get_db_connection() as conn:
        conn.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', (key, value))
        conn.commit()


def perform_backup_and_send_email() -> tuple[bool, str]:
    try:
        smtp_server = get_setting('smtp_server')
        smtp_port = int(get_setting('smtp_port') or '587')
        smtp_user = get_setting('smtp_user')
        smtp_password = get_setting('smtp_password')
        backup_email = get_setting('backup_email')

        if not all([smtp_server, smtp_user, smtp_password, backup_email]):
            return False, "Configuracoes de backup incompletas."

        msg = MIMEMultipart()
        msg['From'] = smtp_user
        msg['To'] = backup_email
        msg['Subject'] = f"Backup ServList - {datetime.now().strftime('%Y-%m-%d')}"

        body = "Segue em anexo o backup do banco de dados do sistema ServList."
        msg.attach(MIMEText(body, 'plain'))

        with open(db_path, "rb") as attachment:
            part = MIMEBase("application", "octet-stream")
            part.set_payload(attachment.read())

        encoders.encode_base64(part)
        part.add_header(
            "Content-Disposition",
            f"attachment; filename=servlist_backup_{datetime.now().strftime('%Y%m%d')}.db",
        )
        msg.attach(part)

        # Connect to server
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(smtp_user, smtp_password)
        text = msg.as_string()
        server.sendmail(smtp_user, backup_email, text)
        server.quit()

        return True, "Backup enviado com sucesso."
    except Exception as e:
        return False, f"Erro ao enviar backup: {str(e)}"


@scheduler.task('cron', id='daily_backup', hour=0, minute=0)
def scheduled_backup_job():
    with app.app_context():
        success, message = perform_backup_and_send_email()
        print(f"[Backup Job] {message}")


@app.get('/api/settings/backup')
def get_backup_settings():
    user, auth_error = require_auth()
    if auth_error:
        return auth_error

    settings = {
        'smtpServer': get_setting('smtp_server'),
        'smtpPort': get_setting('smtp_port', '587'),
        'smtpUser': get_setting('smtp_user'),
        'backupEmail': get_setting('backup_email'),
        # Never return password
    }
    return jsonify({'settings': settings})


@app.post('/api/settings/backup')
def save_backup_settings():
    user, auth_error = require_auth()
    if auth_error:
        return auth_error

    payload = request.get_json(silent=True) or {}

    set_setting('smtp_server', str(payload.get('smtpServer', '')).strip())
    set_setting('smtp_port', str(payload.get('smtpPort', '587')).strip())
    set_setting('smtp_user', str(payload.get('smtpUser', '')).strip())
    set_setting('backup_email', str(payload.get('backupEmail', '')).strip())

    password = str(payload.get('smtpPassword', '')).strip()
    if password:
        set_setting('smtp_password', password)

    return jsonify({'ok': True})


@app.post('/api/backup/test')
def test_backup():
    user, auth_error = require_auth()
    if auth_error:
        return auth_error

    success, message = perform_backup_and_send_email()
    if not success:
        return jsonify({'error': message}), 500

    return jsonify({'ok': True, 'message': message})


@app.route('/api/backup/download', methods=['GET'])
def download_backup():
    user, auth_error = require_auth()
    if auth_error:
        return auth_error

    try:
        if not os.path.exists(db_path):
            return jsonify({'error': 'Database file not found'}), 404
        
        return send_file(
            db_path,
            as_attachment=True,
            download_name=f"servlist_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db",
            mimetype='application/x-sqlite3'
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/backup/restore', methods=['POST'])
def restore_backup():
    user, auth_error = require_auth()
    if auth_error:
        return auth_error

    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
        
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
        
    if file and file.filename.endswith('.db'):
        try:
            # Create a backup of the current DB just in case
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_path = f"{db_path}.bak_{timestamp}"
            shutil.copy2(db_path, backup_path)
            
            # Save the new file
            file.save(db_path)
            
            return jsonify({'success': True, 'message': 'Database restored successfully'})
        except Exception as e:
            return jsonify({'error': str(e)}), 500
            
    return jsonify({'error': 'Invalid file type. Please upload a .db file'}), 400


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
