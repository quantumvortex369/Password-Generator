#  Generador de Contraseñas Seguras

[![Python](https://img.shields.io/badge/Python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

Un generador de contraseñas seguro y versátil con múltiples opciones de personalización, evaluación de fortaleza y almacenamiento seguro.

##  Características Principales

-  **Generación de contraseñas seguras** con múltiples opciones de personalización
-  **Generación de frases de contraseña** fáciles de recordar
-  **Evaluación de fortaleza** detallada con estimación de tiempo de descifrado
-  **Almacenamiento seguro** de contraseñas con cifrado AES-256
-  **Interfaz de línea de comandos** intuitiva
-  **Exportación e importación** de contraseñas a CSV
-  **Soporte para múltiples idiomas** en frases de contraseña
-  **Generación basada en patrones** personalizables

##  Instalación

1. **Clona el repositorio:**
   ```bash
   git clone https://github.com/tuusuario/secure-password-generator.git
   cd secure-password-generator
   ```

2. **Crea y activa un entorno virtual (recomendado):**
   ```bash
   # En Windows
   python -m venv venv
   .\venv\Scripts\activate
   
   # En Unix o MacOS
   python -m venv venv
   source venv/bin/activate
   ```

3. **Instala las dependencias:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Instala el paquete en modo desarrollo:**
   ```bash
   pip install -e .
   ```

##  Uso Rápido

### Generar una contraseña segura
```bash
passgen generate -l 16
```

### Generar una frase de contraseña
```bash
passgen phrase -w 5 --number --symbol
```

### Verificar la fortaleza de una contraseña
```bash
passgen check "TuContraseña123"
```

##  Comandos Disponibles

| Comando | Descripción |
|---------|-------------|
| `generate` | Genera una contraseña segura |
| `phrase` | Genera una frase de contraseña |
| `check` | Verifica la fortaleza de una contraseña |
| `save` | Guarda una contraseña de forma segura |
| `list` | Muestra las contraseñas guardadas |
| `export` | Exporta las contraseñas a un archivo CSV |
| `import` | Importa contraseñas desde un archivo CSV |

##  Ejemplos de Uso

### Generar una contraseña con requisitos específicos
```bash
# Generar contraseña de 20 caracteres sin símbolos
export PASSWORD=$(passgen generate -l 20 --no-symbols)
echo "Tu contraseña es: $PASSWORD"
```

### Generar y guardar una contraseña para un servicio
```bash
# Generar y guardar contraseña para Gmail
passgen save -s Gmail -u usuario@gmail.com -p "$(passgen generate -l 24)"
```

### Verificar la fortaleza de una contraseña
```bash
passgen check "MiSuperContraseña123!"
```

##  Desarrollo

### Estructura del Proyecto
```
password_generator/
├── __init__.py          # Inicialización del paquete
├── generator.py         # Generación de contraseñas
├── strength_checker.py  # Evaluación de fortaleza
├── passphrase_generator.py # Generación de frases
├── storage.py           # Almacenamiento seguro
└── cli.py              # Interfaz de línea de comandos
```

### Ejecutar pruebas
```bash
python -m pytest tests/
```

### Formatear el código
```bash
black .
```

##  Contribuciones

¡Las contribuciones son bienvenidas! Por favor, sigue estos pasos:

1. Haz un fork del proyecto
2. Crea una rama para tu característica (`git checkout -b feature/nueva-funcionalidad`)
3. Haz commit de tus cambios (`git commit -am 'Añade nueva funcionalidad'`)
4. Haz push a la rama (`git push origin feature/nueva-funcionalidad`)
5. Abre un Pull Request
