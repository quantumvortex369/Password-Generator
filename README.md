## Generador de Contraseñas Seguras en Python
-------------------------------------------
Este script en Python te permite generar contraseñas fuertes, aleatorias y seguras de forma rápida desde la terminal. Ideal para reforzar tu seguridad digital o integrarlo en bots, gestores de contraseñas, formularios, y más.

 Características
 ----------------
 -Generación de contraseñas aleatorias

 -Soporte para letras mayúsculas y minúsculas

 -Números incluidos

 -Símbolos especiales añadidos

 -Longitud configurable desde el código

 -Código limpio y ligero

¿Cómo funciona?
----------------
El script define cuatro grupos de caracteres:

```bash
lower = "abcdefghijklmnopqrstuvwxyz"
upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
numbers = "0123456789"
symbols = "!·$%&/()=?¿"
```

Luego combina todos en uno y genera una contraseña de longitud fija usando:

```bash
password = "".join(random.sample(all, length))
```

Esto selecciona los caracteres sin repetición, lo cual es importante tenerlo en cuenta si usas longitudes muy largas.



Requisitos
-----------
 -Python 3.6 o superior

 -Conocimientos básicos de terminal o consola



 Instrucciones de uso
 ---------------------
 
 -Clona el repositorio
```bash
git clone https://github.com/quantumvortex369/Password-Generator.git
```
 -Introduce la ruta del archivo
 
 ```bash
cd Password-Generator
```

 -Ejecuta el script
```bash
python3 password-Generator.py
```
 -Cada ejecución imprimirá una nueva contraseña aleatoria por terminal.


Personalización rápida
------------------------
Para cambiar la longitud de la contraseña, edita esta línea en el código:

```bash
length = 16
```

Cambia 16 por el número de caracteres que desees
 -Seguridad y advertencia
 
 -IMPORTANTE: El script usa random, que no es criptográficamente seguro.
Para aplicaciones sensibles (Criptomonedas, autenticaciones críticas, cifrado, etc.), se recomienda usar el módulo secrets):

Versión segura con secrets:

```bash
import secrets
```

```bash
password = ''.join(secrets.choice(all) for _ in range(length))
```

 -Ejemplos de integración

 
Este script puede integrarse fácilmente en otros proyectos como:

 -Bots en Python

 -Formularios web

 -Scripts CLI personalizados

 -Gestores de contraseñas
