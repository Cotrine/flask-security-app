import re
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError

class PasswordStrengthValidator:
    """
    Validador personalizado de fortaleza de contraseña:
    - Mínimo 8 caracteres.
    - Al menos una letra mayúscula (A-Z).
    - Al menos un dígito numérico (0-9).
    """
    def __call__(self, form, field):
        password = field.data or ''
        if len(password) < 8:
            raise ValidationError("La contraseña debe tener al menos 8 caracteres.")
        if not re.search(r'[A-Z]', password):
            raise ValidationError("La contraseña debe incluir al menos una letra mayúscula (A-Z).")
        if not re.search(r'\d', password):
            raise ValidationError("La contraseña debe incluir al menos un número (0-9).")

class RegistrationForm(FlaskForm):
    """
    Formulario de registro seguro con protección CSRF automática de Flask-WTF.
    """
    email = StringField(
        'Correo Electrónico',
        validators=[
            DataRequired(message="El correo electrónico es obligatorio."),
            Email(message="Ingresa un correo electrónico con formato válido (ejemplo@dominio.com).")
        ]
    )
    password = PasswordField(
        'Contraseña',
        validators=[
            DataRequired(message="La contraseña es obligatoria."),
            PasswordStrengthValidator()
        ]
    )
    confirm_password = PasswordField(
        'Confirmar Contraseña',
        validators=[
            DataRequired(message="Por favor confirma tu contraseña."),
            EqualTo('password', message="Las contraseñas no coinciden.")
        ]
    )
    rol = SelectField(
        'Rol de Usuario',
        choices=[('usuario', 'Usuario'), ('administrador', 'Administrador')],
        default='usuario',
        validators=[DataRequired()]
    )
    submit = SubmitField('Crear Cuenta')


class LoginForm(FlaskForm):
    """
    Formulario de inicio de sesión seguro con protección CSRF.
    """
    email = StringField(
        'Correo Electrónico',
        validators=[
            DataRequired(message="El correo electrónico es obligatorio."),
            Email(message="Ingresa un correo electrónico válido.")
        ]
    )
    password = PasswordField(
        'Contraseña',
        validators=[
            DataRequired(message="La contraseña es obligatoria.")
        ]
    )
    submit = SubmitField('Iniciar Sesión')
