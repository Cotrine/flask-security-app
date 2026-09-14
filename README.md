# 🔒 Proyecto de Seguridad Informática — Flask + PostgreSQL Puro

Aplicación web modular construida en **Python + Flask** con **PostgreSQL puro (usando `psycopg2`, sin ORM ni SQLAlchemy)**, orientada al aprendizaje práctico de principios de seguridad en aplicaciones web y despliegue en la nube (AWS).

---

## 🛡️ Principios y Medidas de Seguridad Implementadas

1. **Inmunidad a Inyección SQL (CWE-89)**:
   - Toda interacción con la base de datos se realiza mediante sentencias preparadas y consultas parametrizadas (`%s`).
   - Se prohíbe explícitamente el uso de concatenación de cadenas o `f-strings` para construir consultas SQL.
2. **Almacenamiento Seguro de Contraseñas (CWE-256)**:
   - Hashing criptográfico robusto utilizando **Bcrypt** (`Flask-Bcrypt`) con sal (*salt*) automática por usuario.
   - En ningún momento se compara o almacena contraseñas en texto plano.
3. **Control de Acceso Basado en Roles (RBAC)**:
   - Decorador `@login_required` para zonas privadas generales.
   - Decorador `@admin_required` para zonas restringidas exclusivas de administradores (retorna `403 Forbidden`).
4. **Protección contra Falsificación de Peticiones en Sitios Cruzados (CSRF)**:
   - Validación estricta de tokens CSRF en todos los formularios mediante `Flask-WTF`.
5. **Variables de Entorno Obligatorias (Fail-Safe)**:
   - La aplicación aborta de inmediato (`RuntimeError`) al iniciar si faltan `SECRET_KEY` o `DATABASE_URL`.
6. **Seguridad en Sesiones y Cookies**:
   - `SESSION_COOKIE_HTTPONLY = True` (evita acceso a la cookie de sesión vía JavaScript/XSS).
   - `SESSION_COOKIE_SAMESITE = 'Lax'` (protege contra peticiones cruzadas).

---

## 💻 Configuración Local de la Base de Datos (PostgreSQL)

### Opción 1: Comandos SQL nativos en PostgreSQL (psql)

Abre tu terminal `psql` con el usuario administrador de PostgreSQL (`postgres`) y ejecuta:

```sql
-- 1. Crear el usuario dedicado para la aplicación
CREATE USER seguridad_user WITH PASSWORD 'seguridad_pass';

-- 2. Crear la base de datos asignando al usuario como propietario
CREATE DATABASE seguridad_db OWNER seguridad_user;

-- 3. Conceder todos los privilegios sobre la base de datos
GRANT ALL PRIVILEGES ON DATABASE seguridad_db TO seguridad_user;
```

Si usas PostgreSQL 15 o superior, conéctate a `seguridad_db` y concede permisos sobre el esquema público:
```sql
\c seguridad_db
GRANT ALL ON SCHEMA public TO seguridad_user;
```

### Opción 2: Usar Docker (si tienes Docker Desktop)
En la raíz del proyecto ejecuta:
```bash
docker compose up -d
```
Esto levantará PostgreSQL 16 listo con el usuario `seguridad_user` y la base de datos `seguridad_db`.

---

## 🚀 Instalación y Ejecución Local

1. **Crear y activar el entorno virtual de Python**:
   ```bash
   # En Windows PowerShell:
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   ```

2. **Instalar dependencias**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Configurar el archivo `.env`**:
   Copia el archivo de ejemplo:
   ```bash
   cp .env.example .env
   ```
   Asegúrate de que `DATABASE_URL` contenga tus credenciales locales:
   ```env
   SECRET_KEY=clave_secreta_super_segura_para_desarrollo_local_2026
   DATABASE_URL=postgresql://seguridad_user:seguridad_pass@localhost:5432/seguridad_db
   ```

4. **Inicializar las tablas en PostgreSQL**:
   Ejecuta el comando CLI para crear la tabla `usuarios`:
   ```bash
   flask init-db
   ```

5. **Iniciar el servidor de desarrollo**:
   ```bash
   python run.py
   ```
   Abre tu navegador en: [http://localhost:5000](http://localhost:5000)

---

## 🧪 Ejecución de Pruebas de Seguridad

Para ejecutar la suite completa de pruebas unitarias que verifican CSRF, Bcrypt, validación de contraseñas y RBAC:

```bash
python -m unittest discover tests
```

---

## ☁️ Preparación para Despliegue en AWS (EC2 + RDS)

El proyecto incluye las plantillas listas en la carpeta `deploy/`:
- `deploy/gunicorn.service.example`: Plantilla de servicio systemd para ejecutar la app de forma permanente en Ubuntu 22.04.
- `deploy/nginx.conf.example`: Plantilla de proxy inverso Nginx con soporte de sockets Unix y cabeceras de proxy seguro.
