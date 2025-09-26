""
Pruebas unitarias para el gestor de contraseñas.
"""
import os
import tempfile
import unittest
from datetime import datetime, timedelta

from password_generator.manager import PasswordManager, PasswordEntry, PasswordCategory, PasswordStrength

class TestPasswordManager(unittest.TestCase):
    """Pruebas para la clase PasswordManager."""
    
    def setUp(self):
        """Configuración inicial para las pruebas."""
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, 'test_db.psafe')
        self.master_password = 'una_contraseña_muy_segura_123!'
        self.manager = PasswordManager(storage_path=self.test_dir, 
                                     master_password=self.master_password)
    
    def tearDown(self):
        """Limpieza después de las pruebas."""
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
        os.rmdir(self.test_dir)
    
    def test_encryption_decryption(self):
        """Prueba que el cifrado y descifrado funcionen correctamente."""
        test_data = {'test': 'datos de prueba', 'número': 123, 'lista': [1, 2, 3]}
        
        # Cifrar
        encrypted = self.manager._encrypt_data(test_data)
        self.assertIsInstance(encrypted, str)
        self.assertNotIn('test', encrypted)  # Los datos no deberían ser legibles
        
        # Descifrar
        decrypted = self.manager._decrypt_data(encrypted)
        self.assertEqual(decrypted, test_data)
    
    def test_save_and_load(self):
        """Prueba guardar y cargar la base de datos."""
        # Añadir algunos datos de prueba
        category = PasswordCategory(
            id='cat1',
            name='Redes Sociales',
            description='Cuentas de redes sociales'
        )
        self.manager.add_category(category)
        
        entry = PasswordEntry(
            id='entry1',
            title='Facebook',
            username='usuario@ejemplo.com',
            password='mi_contraseña_secreta',
            category_id='cat1',
            notes='Cuenta personal',
            website='https://facebook.com'
        )
        self.manager.add_entry(entry)
        
        # Guardar
        self.assertTrue(self.manager.save(self.db_path))
        self.assertTrue(os.path.exists(self.db_path))
        
        # Crear un nuevo gestor y cargar los datos
        new_manager = PasswordManager(storage_path=self.test_dir, 
                                    master_password=self.master_password)
        self.assertTrue(new_manager.load(self.db_path))
        
        # Verificar que los datos se cargaron correctamente
        loaded_category = new_manager.get_category('cat1')
        self.assertIsNotNone(loaded_category)
        self.assertEqual(loaded_category.name, 'Redes Sociales')
        
        loaded_entry = new_manager.get_entry('entry1')
        self.assertIsNotNone(loaded_entry)
        self.assertEqual(loaded_entry.title, 'Facebook')
        self.assertEqual(loaded_entry.username, 'usuario@ejemplo.com')
    
    def test_password_strength(self):
        """Prueba la evaluación de la fortaleza de contraseñas."""
        # Contraseña muy débil
        self.assertEqual(
            self.manager.get_password_strength('123456'),
            PasswordStrength.VERY_WEAK
        )
        
        # Contraseña débil
        self.assertEqual(
            self.manager.get_password_strength('password123'),
            PasswordStrength.WEAK
        )
        
        # Contraseña moderada
        self.assertEqual(
            self.manager.get_password_strength('Password123'),
            PasswordStrength.MODERATE
        )
        
        # Contraseña fuerte
        self.assertEqual(
            self.manager.get_password_strength('P@ssw0rd123!'),
            PasswordStrength.STRONG
        )
        
        # Contraseña muy fuerte
        self.assertEqual(
            self.manager.get_password_strength('V3ry$3cur3P@ssw0rd!2023'),
            PasswordStrength.VERY_STRONG
        )
    
    def test_generate_password(self):
        """Prueba la generación de contraseñas."""
        # Generar contraseña por defecto
        password = self.manager.generate_password()
        self.assertEqual(len(password), 16)
        
        # Generar contraseña con longitud personalizada
        password = self.manager.generate_password(length=20)
        self.assertEqual(len(password), 20)
        
        # Generar contraseña solo con números
        password = self.manager.generate_password(
            length=10,
            use_upper=False,
            use_lower=False,
            use_symbols=False,
            use_digits=True
        )
        self.assertTrue(password.isdigit())
        
        # Generar contraseña con todos los caracteres especiales
        password = self.manager.generate_password(
            length=30,
            use_upper=True,
            use_lower=True,
            use_digits=True,
            use_symbols=True,
            use_brackets=True,
            use_punctuation=True,
            use_math=True,
            use_space=True
        )
        self.assertGreaterEqual(len(password), 30)
        self.assertTrue(any(c.isupper() for c in password))
        self.assertTrue(any(c.islower() for c in password))
        self.assertTrue(any(c.isdigit() for c in password))
        self.assertTrue(any(not c.isalnum() for c in password))

class TestPasswordEntry(unittest.TestCase):
    """Pruebas para la clase PasswordEntry."""
    
    def test_password_entry_creation(self):
        """Prueba la creación de una entrada de contraseña."""
        entry = PasswordEntry(
            id='test1',
            title='Cuenta de Prueba',
            username='usuario',
            password='contraseña',
            website='https://ejemplo.com',
            notes='Notas de prueba',
            category_id='cat1',
            strength=PasswordStrength.STRONG,
            tags=['importante', 'trabajo']
        )
        
        self.assertEqual(entry.id, 'test1')
        self.assertEqual(entry.title, 'Cuenta de Prueba')
        self.assertEqual(entry.username, 'usuario')
        self.assertEqual(entry.password, 'contraseña')
        self.assertEqual(entry.website, 'https://ejemplo.com')
        self.assertEqual(entry.notes, 'Notas de prueba')
        self.assertEqual(entry.category_id, 'cat1')
        self.assertEqual(entry.strength, PasswordStrength.STRONG)
        self.assertEqual(entry.tags, ['importante', 'trabajo'])
        self.assertIsNotNone(entry.created_at)
        self.assertIsNotNone(entry.updated_at)
        self.assertIsNone(entry.last_used)
        self.assertIsNone(entry.expires_at)
    
    def test_password_entry_serialization(self):
        """Prueba la serialización y deserialización de una entrada de contraseña."""
        entry = PasswordEntry(
            id='test1',
            title='Cuenta de Prueba',
            username='usuario',
            password='contraseña',
            website='https://ejemplo.com',
            notes='Notas de prueba',
            category_id='cat1',
            strength=PasswordStrength.STRONG,
            tags=['importante', 'trabajo'],
            created_at=datetime(2023, 1, 1),
            updated_at=datetime(2023, 1, 2),
            last_used=datetime(2023, 1, 3),
            expires_at=datetime(2024, 1, 1)
        )
        
        # Convertir a diccionario
        entry_dict = entry.to_dict()
        self.assertEqual(entry_dict['id'], 'test1')
        self.assertEqual(entry_dict['title'], 'Cuenta de Prueba')
        self.assertEqual(entry_dict['username'], 'usuario')
        self.assertEqual(entry_dict['password'], 'contraseña')
        self.assertEqual(entry_dict['website'], 'https://ejemplo.com')
        self.assertEqual(entry_dict['notes'], 'Notas de prueba')
        self.assertEqual(entry_dict['category_id'], 'cat1')
        self.assertEqual(entry_dict['strength'], 'STRONG')
        self.assertEqual(entry_dict['tags'], ['importante', 'trabajo'])
        self.assertEqual(entry_dict['created_at'], '2023-01-01T00:00:00')
        self.assertEqual(entry_dict['updated_at'], '2023-01-02T00:00:00')
        self.assertEqual(entry_dict['last_used'], '2023-01-03T00:00:00')
        self.assertEqual(entry_dict['expires_at'], '2024-01-01T00:00:00')
        
        # Crear una nueva entrada a partir del diccionario
        new_entry = PasswordEntry.from_dict(entry_dict)
        self.assertEqual(new_entry.id, 'test1')
        self.assertEqual(new_entry.title, 'Cuenta de Prueba')
        self.assertEqual(new_entry.username, 'usuario')
        self.assertEqual(new_entry.password, 'contraseña')
        self.assertEqual(new_entry.website, 'https://ejemplo.com')
        self.assertEqual(new_entry.notes, 'Notas de prueba')
        self.assertEqual(new_entry.category_id, 'cat1')
        self.assertEqual(new_entry.strength, PasswordStrength.STRONG)
        self.assertEqual(new_entry.tags, ['importante', 'trabajo'])
        self.assertEqual(new_entry.created_at, datetime(2023, 1, 1))
        self.assertEqual(new_entry.updated_at, datetime(2023, 1, 2))
        self.assertEqual(new_entry.last_used, datetime(2023, 1, 3))
        self.assertEqual(new_entry.expires_at, datetime(2024, 1, 1))

class TestPasswordCategory(unittest.TestCase):
    """Pruebas para la clase PasswordCategory."""
    
    def test_category_creation(self):
        """Prueba la creación de una categoría."""
        category = PasswordCategory(
            id='cat1',
            name='Redes Sociales',
            description='Cuentas de redes sociales',
            parent_id=None,
            icon='social',
            color='#3b5998'
        )
        
        self.assertEqual(category.id, 'cat1')
        self.assertEqual(category.name, 'Redes Sociales')
        self.assertEqual(category.description, 'Cuentas de redes sociales')
        self.assertIsNone(category.parent_id)
        self.assertEqual(category.icon, 'social')
        self.assertEqual(category.color, '#3b5998')
        self.assertIsNotNone(category.created_at)
        self.assertIsNotNone(category.updated_at)
    
    def test_category_serialization(self):
        """Prueba la serialización y deserialización de una categoría."""
        category = PasswordCategory(
            id='cat1',
            name='Redes Sociales',
            description='Cuentas de redes sociales',
            parent_id=None,
            icon='social',
            color='#3b5998',
            created_at=datetime(2023, 1, 1),
            updated_at=datetime(2023, 1, 2)
        )
        
        # Convertir a diccionario
        category_dict = category.to_dict()
        self.assertEqual(category_dict['id'], 'cat1')
        self.assertEqual(category_dict['name'], 'Redes Sociales')
        self.assertEqual(category_dict['description'], 'Cuentas de redes sociales')
        self.assertIsNone(category_dict['parent_id'])
        self.assertEqual(category_dict['icon'], 'social')
        self.assertEqual(category_dict['color'], '#3b5998')
        self.assertEqual(category_dict['created_at'], '2023-01-01T00:00:00')
        self.assertEqual(category_dict['updated_at'], '2023-01-02T00:00:00')
        
        # Crear una nueva categoría a partir del diccionario
        new_category = PasswordCategory.from_dict(category_dict)
        self.assertEqual(new_category.id, 'cat1')
        self.assertEqual(new_category.name, 'Redes Sociales')
        self.assertEqual(new_category.description, 'Cuentas de redes sociales')
        self.assertIsNone(new_category.parent_id)
        self.assertEqual(new_category.icon, 'social')
        self.assertEqual(new_category.color, '#3b5998')
        self.assertEqual(new_category.created_at, datetime(2023, 1, 1))
        self.assertEqual(new_category.updated_at, datetime(2023, 1, 2))

if __name__ == '__main__':
    unittest.main()
