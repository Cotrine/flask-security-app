from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from .. import bcrypt
from ..db import get_user_by_email, create_user
from .forms import RegistrationForm, LoginForm

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """
    Ruta de registro:
    1. Valida el formulario y tokens CSRF.
    2. Hashea la contraseña con Bcrypt (nunca guarda texto plano).
    3. Registra al usuario en PostgreSQL mediante consultas parametrizadas.
    """
    if 'user_id' in session:
        return redirect(url_for('main.dashboard'))

    form = RegistrationForm()
    if form.validate_on_submit():
        email = form.email.data.lower().strip()
        existing_user = get_user_by_email(email)
        
        if existing_user:
            flash("Ese correo electrónico ya se encuentra registrado. Inicia sesión.", "warning")
            return redirect(url_for('auth.login'))

        # PASO 3: Generación del Hash seguro con Salt automático usando Bcrypt
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        rol = form.rol.data

        try:
            create_user(email=email, password_hash=hashed_password, rol=rol)
            flash("¡Registro exitoso! Ya puedes iniciar sesión de forma segura.", "success")
            return redirect(url_for('auth.login'))
        except Exception as e:
            flash(f"Error al registrar usuario en la base de datos: {e}", "danger")

    return render_template('auth/register.html', form=form)


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """
    Ruta de inicio de sesión:
    1. Verifica la existencia del usuario en PostgreSQL.
    2. Compara el hash Bcrypt contra la contraseña ingresada.
    3. Inicializa la sesión segura en el servidor.
    """
    if 'user_id' in session:
        return redirect(url_for('main.dashboard'))

    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data.lower().strip()
        user = get_user_by_email(email)

        # PASO 3: Verificación segura del hash (Bcrypt)
        if user and bcrypt.check_password_hash(user['password_hash'], form.password.data):
            session.clear() # Previene fijación de sesión (Session Fixation)
            session['user_id'] = user['id']
            session['user_email'] = user['email']
            session['user_rol'] = user['rol']

            flash(f"Bienvenido de nuevo, {user['email']}.", "success")

            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)

            if user['rol'] == 'administrador':
                return redirect(url_for('admin.dashboard'))
            return redirect(url_for('main.dashboard'))
        else:
            flash("Credenciales incorrectas. Verifica tu correo y contraseña.", "danger")

    return render_template('auth/login.html', form=form)


@auth_bp.route('/logout')
def logout():
    """
    Cierra la sesión del usuario invalidando las cookies y limpiando el contexto.
    """
    session.clear()
    flash("Has cerrado sesión exitosamente.", "info")
    return redirect(url_for('auth.login'))
