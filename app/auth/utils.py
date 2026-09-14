from functools import wraps
from flask import session, redirect, url_for, flash, abort, request

def login_required(f):
    """
    Decorador que restringe el acceso solo a usuarios con sesión activa.
    Si no está autenticado, redirige al login.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Debes iniciar sesión para acceder a esta página.", "warning")
            return redirect(url_for('auth.login', next=request.path))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """
    Decorador que restringe el acceso únicamente a usuarios con rol 'administrador'.
    Cumple con el Principio de Mínimo Privilegio (PoLP).
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Debes iniciar sesión con una cuenta de administrador.", "warning")
            return redirect(url_for('auth.login', next=request.path))
        
        user_rol = session.get('user_rol')
        if user_rol != 'administrador':
            flash("Acceso denegado: Se requieren privilegios de administrador.", "danger")
            abort(403) # 403 Forbidden
            
        return f(*args, **kwargs)
    return decorated_function
