#!/usr/bin/env python3
import os
import openai
import pandas as pd
from PIL import Image
import pytesseract
pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'

def extract_text_from_file(file_path):
    """
    Extrae el texto desde el archivo de entrada.
    Se utiliza OCR en caso de imagen (png, jpg) o se lee directamente el contenido
    de un archivo .txt.
    """
    file_path = file_path.strip()
    lower_file = file_path.lower()
    if lower_file.endswith(('.png', '.jpg', '.jpeg')):
        try:
            image = Image.open(file_path)
            # Puedes ajustar el idioma de OCR, por ejemplo 'spa' para español.
            text = pytesseract.image_to_string(image, lang='spa')
            return text
        except Exception as e:
            raise RuntimeError(f"Error procesando la imagen: {e}")
    elif lower_file.endswith('.txt'):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            raise RuntimeError(f"Error leyendo el archivo de texto: {e}")
    else:
        raise ValueError(f"Tipo de archivo no soportado: {file_path}")

def read_asvs_excel(excel_path):
    """
    Lee el archivo Excel que contiene los controles de seguridad OWASP ASVS.
    Se espera que el Excel incluya columnas que describan el identificador y
    la descripción de cada control.
    """
    try:
        df = pd.read_excel(excel_path)
        # Convertimos el DataFrame a string para incluirlo en el prompt
        return df.to_string(index=False)
    except Exception as e:
        raise RuntimeError(f"Error al leer el archivo Excel: {e}")

def analyze_requirements(asvs_info, input_text, api_key):
    """
    Envía un prompt a la API de OpenAI con la información de los controles ASVS y
    la descripción del nuevo requerimiento de software, solicitando una lista de
    controles recomendados junto con una breve explicación.
    """
    openai.api_key = api_key
    prompt = f"""Eres un experto en seguridad de software. A continuación tienes un listado de controles de seguridad 
bajo el estándar OWASP ASVS:

{asvs_info}

Se te presenta el siguiente requerimiento de software:

{input_text}

Por favor, analiza la información y sugiere cuál o cuáles controles de seguridad de ASVS son los más convenientes 
para este caso, indicando brevemente la razón para cada control recomendado.
"""
    try:
        response = openai.ChatCompletion.create(
            model="gpt-4o-2024-05-13",
            messages=[
                {"role": "system", "content": "Eres un asesor experto en seguridad de software."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3
        )
        return response.choices[0].message.content
    except Exception as e:
        raise RuntimeError(f"Error al llamar a la API de OpenAI: {e}")

def main():
    # Parámetros definidos directamente en el código:
    ASVS_FILE = "owasp/req-asvs.xlsx"         # Archivo Excel con los controles OWASP ASVS.
    INPUT_FILE = "owasp/input-feature.png"     # Archivo que contiene detalles del nuevo requerimiento (puede ser imagen o .txt).
    OPENAI_API_KEY = "xxxxxxxxxxxxxxx"  # Reemplaza con tu API key de OpenAI.
    
    # Opcionalmente, se puede utilizar la variable de entorno si está definida.
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", OPENAI_API_KEY)
    if not OPENAI_API_KEY:
        print("Error: Es necesaria la API key de OpenAI. Configúrala en el script o en la variable de entorno OPENAI_API_KEY.")
        exit(1)

    # Procesar el archivo Excel con los controles ASVS.
    try:
        asvs_info = read_asvs_excel(ASVS_FILE)
    except Exception as e:
        print(f"Error al procesar el archivo ASVS '{ASVS_FILE}': {e}")
        exit(1)
    
    # Procesar el archivo con la descripción del requerimiento.
    try:
        input_text = extract_text_from_file(INPUT_FILE)
    except Exception as e:
        print(f"Error al procesar el archivo de entrada '{INPUT_FILE}': {e}")
        exit(1)
    
    # Llamar a la API de OpenAI para obtener los controles recomendados.
    try:
        result = analyze_requirements(asvs_info, input_text, OPENAI_API_KEY)
        print("\nControles ASVS recomendados:\n")
        print(result)
    except Exception as e:
        print(e)
        exit(1)

if __name__ == "__main__":
    main() 