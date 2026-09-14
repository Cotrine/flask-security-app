"""
Módulo de conexión y operaciones de base de datos con PostgreSQL Puro.
Usa psycopg2 sin ORM (sin SQLAlchemy) y consultas estrictamente parametrizadas
para mitigar vulnerabilidades de Inyección SQL (CWE-89).
"""

import os
import psycopg2
from psycopg2.extras import DictCursor
from flask import g, current_app
import click

def get_db():
    """
    Obtiene o crea una conexión a PostgreSQL dentro del contexto de la petición de Flask.
    """
    if 'db' not in g:
        database_url = current_app.config['DATABASE_URL']
        try:
            g.db = psycopg2.connect(database_url)
        except Exception as e:
            current_app.logger.error(f"Error al conectar con PostgreSQL: {e}")
            raise RuntimeError(
                f"No se pudo conectar a la base de datos PostgreSQL en DATABASE_URL. Error: {e}"
            ) from e
    return g.db

def close_db(e=None):
    """Cierra la conexión a la base de datos al finalizar la petición."""
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    """Ejecuta el archivo schema.sql para crear las tablas si no existen."""
    db = get_db()
    schema_path = os.path.join(os.path.dirname(__file__), 'schema.sql')
    with open(schema_path, 'r', encoding='utf-8') as f:
        sql = f.read()
    with db.cursor() as cursor:
        cursor.execute(sql)
    db.commit()

@click.command('init-db')
def init_db_command():
    """Comando CLI para inicializar las tablas de la base de datos."""
    init_db()
    click.echo("Base de datos PostgreSQL inicializada con éxito (tabla 'usuarios').")

def init_app(app):
    """Registra las funciones de cierre e inicialización en la aplicación Flask."""
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)

# =========================================================================
# Consultas SQL Parametrizadas (Seguras contra Inyección SQL)
# =========================================================================

def get_user_by_email(email):
    """
    Busca un usuario por su email usando consultas preparadas parametrizadas (%s).
    """
    db = get_db()
    with db.cursor(cursor_factory=DictCursor) as cursor:
        # NUNCA usar concatenación de cadenas como f"SELECT ... WHERE email = '{email}'"
        cursor.execute(
            "SELECT id, email, password_hash, rol, fecha_registro FROM usuarios WHERE email = %s;",
            (email.lower().strip(),)
        )
        return cursor.fetchone()

def get_user_by_id(user_id):
    """Busca un usuario por su ID primario."""
    db = get_db()
    with db.cursor(cursor_factory=DictCursor) as cursor:
        cursor.execute(
            "SELECT id, email, password_hash, rol, fecha_registro FROM usuarios WHERE id = %s;",
            (user_id,)
        )
        return cursor.fetchone()

def create_user(email, password_hash, rol='usuario'):
    """
    Inserta un nuevo usuario con contraseña hasheada y rol especificado.
    """
    db = get_db()
    with db.cursor(cursor_factory=DictCursor) as cursor:
        cursor.execute(
            """
            INSERT INTO usuarios (email, password_hash, rol)
            VALUES (%s, %s, %s)
            RETURNING id, email, rol, fecha_registro;
            """,
            (email.lower().strip(), password_hash, rol)
        )
        user = cursor.fetchone()
        db.commit()
        return user

def get_all_users():
    """Obtiene la lista de usuarios para el panel de administración."""
    db = get_db()
    with db.cursor(cursor_factory=DictCursor) as cursor:
        cursor.execute(
            "SELECT id, email, rol, fecha_registro FROM usuarios ORDER BY id ASC;"
        )
        return cursor.fetchall()
