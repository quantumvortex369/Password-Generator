"""Módulo principal de la interfaz gráfica del generador de contraseñas."""
import tkinter as tk
from tkinter import ttk, messagebox
import pyperclip
from ..core.generator import PasswordGenerator
from ..core.passphrase_generator import PassphraseGenerator
from ..security.strength import PasswordStrengthChecker

class PasswordGeneratorApp:
    """Clase principal de la aplicación de generador de contraseñas."""
    
    def __init__(self, root):
        """Inicializa la aplicación."""
        self.root = root
        self.root.title("Generador de Contraseñas Seguras")
        self.root.geometry("600x500")
        self.root.resizable(True, True)
        
        # Configurar estilo
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self._setup_styles()
        
        # Inicializar generador y verificador de fortaleza
        self.generator = PasswordGenerator()
        self.strength_checker = PasswordStrengthChecker()
        
        # Variables de control para la pestaña de contraseña
        self.password_var = tk.StringVar()
        self.length_var = tk.IntVar(value=16)
        self.strength_var = tk.StringVar(value="Fuerza: -")
        self.use_upper = tk.BooleanVar(value=True)
        self.use_lower = tk.BooleanVar(value=True)
        self.use_digits = tk.BooleanVar(value=True)
        self.use_symbols = tk.BooleanVar(value=True)
        self.use_brackets = tk.BooleanVar(value=False)
        self.use_punctuation = tk.BooleanVar(value=False)
        self.use_math = tk.BooleanVar(value=False)
        self.use_space = tk.BooleanVar(value=False)
        
        # Variables de control para la pestaña de frases
        self.passphrase_var = tk.StringVar()
        self.num_words_var = tk.IntVar(value=4)
        self.capitalize_var = tk.BooleanVar(value=True)
        self.add_number_var = tk.BooleanVar(value=True)
        self.add_symbol_var = tk.BooleanVar(value=True)
        self.separator_var = tk.StringVar(value="-")
        
        # Inicializar generador de frases
        self.passphrase_gen = PassphraseGenerator()
        
        self._create_widgets()
    
    def _setup_styles(self):
        """Configura los estilos de la interfaz."""
        self.style.configure('TFrame', background='#f0f0f0')
        self.style.configure('TLabel', background='#f0f0f0', font=('Segoe UI', 10))
        self.style.configure('Header.TLabel', font=('Segoe UI', 16, 'bold'))
        self.style.configure('Password.TLabel', font=('Consolas', 12, 'bold'))
        self.style.configure('Strength.TLabel', font=('Segoe UI', 10, 'bold'))
        self.style.configure('TButton', font=('Segoe UI', 10))
        self.style.configure('Generate.TButton', background='#4CAF50', foreground='white')
        self.style.configure('Copy.TButton', background='#2196F3', foreground='white')
        self.style.configure('TCheckbutton', background='#f0f0f0')
        
    def _create_widgets(self):
        """Crea y coloca los widgets en la ventana."""
        # Frame principal
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Título
        title_label = ttk.Label(
            main_frame, 
            text="Generador de Contraseñas Seguras", 
            style='Header.TLabel'
        )
        title_label.pack(pady=(0, 10))
        
        # Crear un notebook (pestañas)
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Pestaña de generador de contraseñas
        self._create_password_tab()
        
        # Pestaña de generador de frases
        self._create_passphrase_tab()
        
    def _create_password_tab(self):
        """Crea la pestaña de generación de contraseñas."""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Contraseña")
        
        # Frame de contraseña generada
        password_frame = ttk.Frame(tab)
        password_frame.pack(fill=tk.X, pady=(10, 20), padx=10)
        
        ttk.Label(password_frame, text="Contraseña generada:").pack(anchor=tk.W)
        
        # Frame para el campo de texto y el botón de copiar
        entry_frame = ttk.Frame(password_frame)
        entry_frame.pack(fill=tk.X, pady=(5, 0))
        
        self.password_entry = ttk.Entry(
            entry_frame, 
            textvariable=self.password_var, 
            font=('Consolas', 12), 
            state='readonly',
            width=40
        )
        self.password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        copy_btn = ttk.Button(
            entry_frame,
            text="Copiar",
            command=self.copy_password_to_clipboard,
            style='Copy.TButton',
            width=10
        )
        copy_btn.pack(side=tk.LEFT)
        
        # Indicador de fortaleza
        self.strength_label = ttk.Label(
            tab,
            textvariable=self.strength_var,
            style='Strength.TLabel'
        )
        self.strength_label.pack(pady=(0, 20))
        
        # Frame de opciones
        options_frame = ttk.LabelFrame(tab, text="Opciones de Contraseña", padding=10)
        options_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 20))
        
        # Longitud
        length_frame = ttk.Frame(options_frame)
        length_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(length_frame, text="Longitud:").pack(side=tk.LEFT, padx=(0, 10))
        
        length_scale = ttk.Scale(
            length_frame,
            from_=8,
            to=64,
            orient=tk.HORIZONTAL,
            variable=self.length_var,
            command=lambda e: self.update_length_display()
        )
        length_scale.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 10))
        
        self.length_display = ttk.Label(length_frame, text="16")
        self.length_display.pack(side=tk.LEFT)
        
        # Checkboxes para tipos de caracteres
        ttk.Checkbutton(
            options_frame, 
            text="Letras mayúsculas (A-Z)", 
            variable=self.use_upper
        ).pack(anchor=tk.W, pady=2)
        
        ttk.Checkbutton(
            options_frame, 
            text="Letras minúsculas (a-z)", 
            variable=self.use_lower
        ).pack(anchor=tk.W, pady=2)
        
        ttk.Checkbutton(
            options_frame, 
            text="Dígitos (0-9)", 
            variable=self.use_digits
        ).pack(anchor=tk.W, pady=2)
        
        ttk.Checkbutton(
            options_frame, 
            text="Símbolos (!@#$%^&*_+-=)", 
            variable=self.use_symbols
        ).pack(anchor=tk.W, pady=2)
        
        # Opciones avanzadas
        advanced_frame = ttk.LabelFrame(options_frame, text="Opciones Avanzadas", padding=10)
        advanced_frame.pack(fill=tk.X, pady=10)
        
        ttk.Checkbutton(
            advanced_frame, 
            text="Incluir paréntesis y corchetes ([](){})", 
            variable=self.use_brackets
        ).pack(anchor=tk.W, pady=2)
        
        ttk.Checkbutton(
            advanced_frame, 
            text="Incluir signos de puntuación (!?.,;:)", 
            variable=self.use_punctuation
        ).pack(anchor=tk.W, pady=2)
        
        ttk.Checkbutton(
            advanced_frame, 
            text="Incluir símbolos matemáticos (+-*/^=)", 
            variable=self.use_math
        ).pack(anchor=tk.W, pady=2)
        
        ttk.Checkbutton(
            advanced_frame, 
            text="Incluir espacio en blanco", 
            variable=self.use_space
        ).pack(anchor=tk.W, pady=2)
        
        # Botón de generar
        generate_btn = ttk.Button(
            tab,
            text="Generar Contraseña",
            command=self.generate_password,
            style='Generate.TButton',
            width=20
        )
        generate_btn.pack(pady=(10, 0))
    
    def update_length_display(self):
        """Actualiza la visualización de la longitud de la contraseña."""
        self.length_display.config(text=str(self.length_var.get()))
    
    def generate_password(self):
        """Genera una nueva contraseña con las opciones seleccionadas."""
        try:
            # Verificar que al menos un tipo de carácter esté seleccionado
            if not any([
                self.use_upper.get(),
                self.use_lower.get(),
                self.use_digits.get(),
                self.use_symbols.get(),
                self.use_brackets.get(),
                self.use_punctuation.get(),
                self.use_math.get(),
                self.use_space.get()
            ]):
                messagebox.showwarning(
                    "Advertencia",
                    "Debes seleccionar al menos un tipo de carácter para la contraseña."
                )
                return
            
            # Generar la contraseña
            password = self.generator.generate_password(
                length=self.length_var.get(),
                use_upper=self.use_upper.get(),
                use_lower=self.use_lower.get(),
                use_digits=self.use_digits.get(),
                use_symbols=self.use_symbols.get(),
                use_brackets=self.use_brackets.get(),
                use_punctuation=self.use_punctuation.get(),
                use_math=self.use_math.get(),
                use_space=self.use_space.get()
            )
            
            # Actualizar la interfaz
            self.password_var.set(password)
            self.update_strength_indicator(password)
            
        except ValueError as e:
            messagebox.showerror("Error", str(e))
    
    def update_strength_indicator(self, password):
        """Actualiza el indicador de fortaleza de la contraseña."""
        strength = self.strength_checker.check_strength(password)
        strength_text = f"Fuerza: {strength.name}"
        self.strength_var.set(strength_text)
        
        # Cambiar el color según la fortaleza
        if strength.value <= 1:
            self.strength_label.config(foreground='red')
        elif strength.value == 2:
            self.strength_label.config(foreground='orange')
        else:
            self.strength_label.config(foreground='green')
    
    def _create_passphrase_tab(self):
        """Crea la pestaña de generación de frases de contraseña."""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Frase de Contraseña")
        
        # Frame de frase generada
        passphrase_frame = ttk.Frame(tab)
        passphrase_frame.pack(fill=tk.X, pady=(10, 20), padx=10)
        
        ttk.Label(passphrase_frame, text="Frase generada:").pack(anchor=tk.W)
        
        # Frame para el campo de texto y el botón de copiar
        entry_frame = ttk.Frame(passphrase_frame)
        entry_frame.pack(fill=tk.X, pady=(5, 0))
        
        # Campo de texto para la frase generada
        self.passphrase_entry = ttk.Entry(
            entry_frame,
            textvariable=self.passphrase_var,
            font=('Segoe UI', 10),
            state='readonly',
            width=40
        )
        self.passphrase_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        # Botón para copiar la frase
        copy_btn = ttk.Button(
            entry_frame,
            text="Copiar",
            command=self.copy_passphrase_to_clipboard,
            style='Copy.TButton',
            width=10
        )
        copy_btn.pack(side=tk.LEFT)
        
        # Frame de opciones
        options_frame = ttk.LabelFrame(tab, text="Opciones de Frase", padding=10)
        options_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 20), padx=10)
        
        # Número de palabras
        ttk.Label(options_frame, text="Número de palabras:").grid(row=0, column=0, sticky=tk.W, pady=2)
        ttk.Spinbox(
            options_frame,
            from_=3,
            to=8,
            textvariable=self.num_words_var,
            width=5
        ).grid(row=0, column=1, sticky=tk.W, pady=2, padx=5)
        
        # Opciones de formato
        ttk.Checkbutton(
            options_frame,
            text="Capitalizar palabras",
            variable=self.capitalize_var
        ).grid(row=1, column=0, columnspan=2, sticky=tk.W, pady=2)
        
        ttk.Checkbutton(
            options_frame,
            text="Añadir número",
            variable=self.add_number_var
        ).grid(row=2, column=0, columnspan=2, sticky=tk.W, pady=2)
        
        ttk.Checkbutton(
            options_frame,
            text="Añadir símbolo",
            variable=self.add_symbol_var
        ).grid(row=3, column=0, columnspan=2, sticky=tk.W, pady=2)
        
        # Separador
        ttk.Label(options_frame, text="Separador:").grid(row=4, column=0, sticky=tk.W, pady=2)
        ttk.Combobox(
            options_frame,
            textvariable=self.separator_var,
            values=['-', '_', '.', ',', ' ', ''],
            width=5,
            state='readonly'
        ).grid(row=4, column=1, sticky=tk.W, pady=2, padx=5)
        
        # Botón de generar frase
        generate_btn = ttk.Button(
            tab,
            text="Generar Frase",
            command=self.generate_passphrase,
            style='Generate.TButton',
            width=20
        )
        generate_btn.pack(pady=(10, 0))
        
        # Etiqueta de fortaleza
        self.passphrase_strength = ttk.Label(
            tab,
            text="",
            style='Strength.TLabel'
        )
        self.passphrase_strength.pack(pady=(10, 0))
    
    def generate_passphrase(self):
        """Genera una nueva frase de contraseña con las opciones seleccionadas."""
        try:
            passphrase = self.passphrase_gen.generate(
                num_words=self.num_words_var.get(),
                capitalize=self.capitalize_var.get(),
                add_number=self.add_number_var.get(),
                add_symbol=self.add_symbol_var.get(),
                separator=self.separator_var.get()
            )
            
            self.passphrase_var.set(passphrase)
            strength = self.passphrase_gen.estimate_strength(passphrase)
            self.passphrase_strength.config(text=f"Fortaleza: {strength}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Error al generar la frase: {str(e)}")
    
    def copy_to_clipboard(self, text_var, message):
        """Copia el texto al portapapeles."""
        text = text_var.get()
        if text:
            pyperclip.copy(text)
            messagebox.showinfo("Copiado", message)
        else:
            messagebox.showwarning("Advertencia", "No hay texto para copiar.")
    
    def copy_password_to_clipboard(self):
        """Copia la contraseña al portapapeles."""
        self.copy_to_clipboard(self.password_var, "La contraseña ha sido copiada al portapapeles.")
    
    def copy_passphrase_to_clipboard(self):
        """Copia la frase de contraseña al portapapeles."""
        self.copy_to_clipboard(self.passphrase_var, "La frase de contraseña ha sido copiada al portapapeles.")

def main():
    """Función principal para iniciar la aplicación."""
    root = tk.Tk()
    app = PasswordGeneratorApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
