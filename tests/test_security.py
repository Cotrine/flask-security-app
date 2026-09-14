import unittest
from unittest.mock import patch, MagicMock
from app import create_app, bcrypt
from app.auth.forms import RegistrationForm

class SecurityTestCase(unittest.TestCase):
    def setUp(self):
        self.test_config = {
            'TESTING': True,
            'WTF_CSRF_ENABLED': False, # Desactivado temporalmente para pruebas funcionales de rutas
            'SECRET_KEY': 'test_secret_key_for_testing_purposes',
            'DATABASE_URL': 'postgresql://test:test@localhost:5432/test_db',
        }
        self.app = create_app(self.test_config)
        self.client = self.app.test_client()

    # -------------------------------------------------------------
    # PASO 7: Validación de variables de entorno obligatorias
    # -------------------------------------------------------------
    def test_mandatory_environment_variables_failure(self):
        """Verifica que la app no arranque si falta SECRET_KEY o DATABASE_URL."""
        with patch.dict('os.environ', {'SECRET_KEY': '', 'DATABASE_URL': ''}, clear=True):
            with self.assertRaises(RuntimeError) as ctx:
                create_app()
            self.assertIn("SECRET_KEY es OBLIGATORIA", str(ctx.exception))

        with patch.dict('os.environ', {'SECRET_KEY': 'clave_valida', 'DATABASE_URL': ''}, clear=True):
            with self.assertRaises(RuntimeError) as ctx:
                create_app()
            self.assertIn("DATABASE_URL es OBLIGATORIA", str(ctx.exception))

    # -------------------------------------------------------------
    # PASO 3 & 4: Hashing con Bcrypt y validaciones de contraseña
    # -------------------------------------------------------------
    def test_bcrypt_hashing_generation_and_verification(self):
        """Verifica que las contraseñas se hasheen con salt y no en texto plano."""
        raw_password = "SecurePassword2026!"
        hashed = bcrypt.generate_password_hash(raw_password).decode('utf-8')

        # El hash debe empezar con el identificador de Bcrypt $2b$
        self.assertTrue(hashed.startswith('$2b$'))
        self.assertNotEqual(raw_password, hashed)

        # Verificación exitosa del hash
        self.assertTrue(bcrypt.check_password_hash(hashed, raw_password))
        # Rechazo ante contraseña errónea
        self.assertFalse(bcrypt.check_password_hash(hashed, "WrongPassword2026!"))

    def test_password_strength_validation(self):
        """Verifica los criterios mínimos: 8 caracteres, 1 mayúscula, 1 número."""
        with self.app.test_request_context():
            # Contraseña muy corta
            form_short = RegistrationForm(email='test@example.com', password='Ab1', confirm_password='Ab1', rol='usuario')
            self.assertFalse(form_short.validate())
            self.assertTrue(any("al menos 8 caracteres" in err for err in form_short.password.errors))

            # Sin mayúsculas
            form_no_upper = RegistrationForm(email='test@example.com', password='password123', confirm_password='password123', rol='usuario')
            self.assertFalse(form_no_upper.validate())
            self.assertTrue(any("letra mayúscula" in err for err in form_no_upper.password.errors))

            # Sin números
            form_no_digit = RegistrationForm(email='test@example.com', password='PasswordSeguro', confirm_password='PasswordSeguro', rol='usuario')
            self.assertFalse(form_no_digit.validate())
            self.assertTrue(any("un número" in err for err in form_no_digit.password.errors))

            # Contraseña válida
            form_valid = RegistrationForm(email='test@example.com', password='PasswordValido123', confirm_password='PasswordValido123', rol='usuario')
            self.assertTrue(form_valid.validate())

    # -------------------------------------------------------------
    # PASO 5: Roles y Control de Acceso (RBAC)
    # -------------------------------------------------------------
    def test_unauthenticated_dashboard_redirects_to_login(self):
        """Verifica que un usuario anónimo sea redirigido a login al entrar a /dashboard."""
        response = self.client.get('/dashboard')
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login', response.headers['Location'])

    def test_admin_dashboard_forbidden_for_standard_user(self):
        """Verifica que un usuario con rol 'usuario' NO pueda entrar al panel admin (403 Forbidden)."""
        with self.client.session_transaction() as sess:
            sess['user_id'] = 1
            sess['user_email'] = 'usuario@ejemplo.com'
            sess['user_rol'] = 'usuario'

        response = self.client.get('/admin/dashboard')
        self.assertEqual(response.status_code, 403)

    @patch('app.admin.routes.get_all_users')
    def test_admin_dashboard_allowed_for_admin_user(self, mock_get_users):
        """Verifica que un usuario con rol 'administrador' SÍ pueda entrar al panel admin."""
        mock_get_users.return_value = [
            {'id': 1, 'email': 'admin@ejemplo.com', 'rol': 'administrador', 'fecha_registro': None}
        ]
        with self.client.session_transaction() as sess:
            sess['user_id'] = 1
            sess['user_email'] = 'admin@ejemplo.com'
            sess['user_rol'] = 'administrador'

        response = self.client.get('/admin/dashboard')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Panel Exclusivo de Administrador", response.data)

    # -------------------------------------------------------------
    # PASO 6: Protección CSRF
    # -------------------------------------------------------------
    def test_csrf_protection_enabled_rejects_missing_token(self):
        """Verifica que con CSRF activo, una petición POST sin token sea rechazada (HTTP 400)."""
        app_with_csrf = create_app({
            'TESTING': True,
            'WTF_CSRF_ENABLED': True,
            'SECRET_KEY': 'test_csrf_secret_key',
            'DATABASE_URL': 'postgresql://test:test@localhost:5432/test_db',
        })
        client_csrf = app_with_csrf.test_client()

        # Petición POST sin token CSRF
        response = client_csrf.post('/login', data={'email': 'test@example.com', 'password': 'Password123'})
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"CSRF token is missing", response.data)

if __name__ == '__main__':
    unittest.main()
