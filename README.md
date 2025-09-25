# Generador de Contraseñas Seguras

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

Un generador de contraseñas seguro y versátil con interfaz de línea de comandos, evaluación de fortaleza y almacenamiento seguro.

## Características Principales

- **Generación de contraseñas seguras** con múltiples opciones de personalización
- **Generación de frases de contraseña** fáciles de recordar
- **Evaluación de fortaleza** con puntuación detallada y sugerencias
- **Almacenamiento seguro** de contraseñas con cifrado
- **Interfaz de línea de comandos** intuitiva
- **Exportación/importación** de contraseñas (JSON/CSV)
- **Verificación de contraseñas comprometidas** usando la API de Have I Been Pwned

## Instalación

1. **Clona el repositorio:**
   ```bash
   git clone https://github.com/quantumvortex369/password-generator.git
   cd password-generator
   ```

2. **Crea y activa un entorno virtual (recomendado):**
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/Mac
   # O en Windows: .\venv\Scripts\activate
   ```

3. **Instala las dependencias:**
   ```bash
   pip install -r requirements.txt
   ```

## Uso Rápido

### Generar una contraseña segura
```bash
python generadordecontrasenas.py -l 16
```

### Generar una frase de contraseña
```bash
python generadordecontrasenas.py -p -w 5
```

### Verificar la fortaleza de una contraseña
```bash
python generadordecontrasenas.py --check "TuContraseña123"
```

## Opciones Disponibles

| Opción | Descripción |
|--------|-------------|
| `-l, --length` | Longitud de la contraseña |
| `-n, --number` | Número de contraseñas a generar |
| `--no-lower` | Excluir letras minúsculas |
| `--no-upper` | Excluir letras mayúsculas |
| `--no-digits` | Excluir números |
| `--no-symbols` | Excluir símbolos |
| `-p, --passphrase` | Generar una frase de contraseña |
| `-w, --words` | Número de palabras para la frase |
| `-c, --copy` | Copiar al portapapeles |
| `-s, --save` | Guardar la contraseña |
| `--service` | Servicio para el que se genera la contraseña |
| `-u, --username` | Nombre de usuario para guardar |
| `--check` | Verificar fortaleza de una contraseña |

## Ejemplos de Uso

### Generar múltiples contraseñas
```bash
# Generar 5 contraseñas de 12 caracteres
python generadordecontrasenas.py -l 12 -n 5
```

### Generar y guardar una contraseña para un servicio
```bash
# Generar contraseña para Gmail y guardarla
python generadordecontrasenas.py -l 24 --service Gmail -u usuario@gmail.com --save
```

### Generar una frase de contraseña segura
```bash
# Frase con 6 palabras, incluyendo números y símbolos
python generadordecontrasenas.py -p -w 6 --no-lower --no-upper
```

## Estructura del Proyecto

```
password_generator/
├── __init__.py          # Inicialización del paquete
├── __main__.py          # Punto de entrada
├── cli/                 # Comandos de línea
│   ├── __init__.py
│   └── main.py
├── core/
│   └── generator.py     # Generación de contraseñas
├── models/
│   └── password.py      # Modelos de datos
├── security/
│   ├── crypto.py        # Funciones criptográficas
│   └── strength.py      # Evaluación de fortaleza
└── storage/
    └── manager.py       # Almacenamiento seguro
```

## Requisitos

- Python 3.8+
- Dependencias en `requirements.txt`
  - cryptography
  - pyperclip
  - requests

## Contribuciones

¡Las contribuciones son bienvenidas! Por favor, sigue estos pasos:

1. Haz un fork del proyecto
2. Crea una rama para tu característica (`git checkout -b feature/nueva-funcionalidad`)
3. Haz commit de tus cambios (`git commit -am 'Añade nueva funcionalidad'`)
4. Haz push a la rama (`git push origin feature/nueva-funcionalidad`)
5. Abre un Pull Request
