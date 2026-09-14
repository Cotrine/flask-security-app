from flask import Blueprint, render_template, session
from ..auth.utils import admin_required
from ..db import get_all_users

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

@admin_bp.route('/dashboard')
@admin_required
def dashboard():
    """
    Ruta exclusiva para administradores protegida mediante el decorador @admin_required.
    Muestra la lista de usuarios registrados en el sistema para fines de auditoría.
    """
    users = get_all_users()
    admin_info = {
        'id': session.get('user_id'),
        'email': session.get('user_email'),
        'rol': session.get('user_rol'),
    }
    return render_template('admin/dashboard.html', users=users, admin=admin_info)
