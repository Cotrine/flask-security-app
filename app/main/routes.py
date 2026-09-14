from flask import Blueprint, render_template, session, redirect, url_for
from ..auth.utils import login_required

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    """Página de bienvenida / Home."""
    if 'user_id' in session:
        return redirect(url_for('main.dashboard'))
    return redirect(url_for('auth.login'))

@main_bp.route('/dashboard')
@login_required
def dashboard():
    """
    Panel privado de usuario estándar protegido con @login_required.
    """
    user_info = {
        'id': session.get('user_id'),
        'email': session.get('user_email'),
        'rol': session.get('user_rol'),
    }
    return render_template('main/dashboard.html', user=user_info)
