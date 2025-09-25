from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="secure-password-generator",
    version="1.0.0",
    author="Tu Nombre",
    author_email="tu@email.com",
    description="Un generador de contraseñas seguras con múltiples opciones",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/tuusuario/secure-password-generator",
    packages=find_packages(),
    package_data={
        'password_generator': ['*.json'],
    },
    install_requires=[
        'cryptography>=3.4.7',
        'pyperclip>=1.8.2',
        'requests>=2.26.0',
    ],
    entry_points={
        'console_scripts': [
            'passgen=password_generator.cli:main',
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)
