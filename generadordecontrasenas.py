import random

lower = "abcdefghijklmnopqrstuvwxyz"
upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
numbers = "0123456789"
symbols = "!·$%&/()=?¿"

all = lower + upper + numbers + symbols

length = 16 # Longitud de la contraseña

password = "".join(random.sample(all, length))  # Genera la contraseña aleatoria

print(password)  # Muestra la contraseña generada