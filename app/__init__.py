import os
from flask import Flask
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv

# Cargar variables de entorno desde .env
load_dotenv()

bcrypt = Bcrypt()
csrf = CSRFProtect()

def create_app(test_config=None):
    """
    Fábrica de aplicaciones Flask (Application Factory).
    Valida variables de entorno obligatorias y configura protecciones de seguridad.
    """
    app = Flask(__name__, instance_relative_config=True)

    # -------------------------------------------------------------
    # PASO 7: Validación de Variables de Entorno OBLIGATORIAS
    # La aplicación debe FALLAR si SECRET_KEY o DATABASE_URL faltan.
    # -------------------------------------------------------------
    secret_key = os.environ.get('SECRET_KEY')
    database_url = os.environ.get('DATABASE_URL')

    if test_config is None:
        if not secret_key or not secret_key.strip():
            raise RuntimeError(
                "[ERROR DE SEGURIDAD]: La variable de entorno SECRET_KEY es OBLIGATORIA. "
                "Define SECRET_KEY en tu archivo .env antes de iniciar la aplicación."
            )
        if not database_url or not database_url.strip():
            raise RuntimeError(
                "[ERROR DE SEGURIDAD]: La variable de entorno DATABASE_URL es OBLIGATORIA. "
                "Define DATABASE_URL (PostgreSQL) en tu archivo .env antes de iniciar la aplicación."
            )
        app.config['SECRET_KEY'] = secret_key
        app.config['DATABASE_URL'] = database_url
    else:
        app.config.update(test_config)

    # Configuración de Seguridad en Sesiones
    app.config['SESSION_COOKIE_HTTPONLY'] = True  # Protege la cookie de sesión contra robo via XSS
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # Mitiga ataques CSRF a nivel de cookie
    app.config['PERMANENT_SESSION_LIFETIME'] = 1800 # Expiración de sesión en 30 minutos

    # Inicializar extensiones de seguridad
    bcrypt.init_app(app)
    csrf.init_app(app)

    # Inicializar base de datos con psycopg2
    from . import db
    db.init_app(app)

    # Registrar Blueprints
    from .auth.routes import auth_bp
    from .main.routes import main_bp
    from .admin.routes import admin_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(admin_bp)

    return app
