#!/usr/bin/env python3
import requests
import json
from datetime import datetime
import time
import os
from typing import List, Dict
from dotenv import load_dotenv

class BreachAnalyzer:
    def __init__(self):
        # Obtener API key desde variable de entorno
        load_dotenv()
        self.HIBP_API_KEY = os.getenv('HIBP_API_KEY')
        if not self.HIBP_API_KEY:
            raise ValueError("La API key de HaveIBeenPwned no está configurada. Configure la variable de entorno HIBP_API_KEY.")
        
        self.BASE_URL = "https://haveibeenpwned.com/api/v3"
        self.headers = {
            'hibp-api-key': self.HIBP_API_KEY,
            'User-Agent': 'BreachAnalyzer Script'
        }
        
    def read_emails(self, file_path: str) -> List[str]:
        """Lee los correos electrónicos desde un archivo de texto."""
        try:
            with open(file_path, 'r') as file:
                # Elimina espacios en blanco y líneas vacías
                emails = [line.strip() for line in file if line.strip()]
            return emails
        except Exception as e:
            raise Exception(f"Error al leer el archivo de correos: {str(e)}")

    def check_breach(self, email: str) -> Dict:
        """Verifica si un correo electrónico ha sido comprometido."""
        try:
            # Espera 1.5 segundos entre solicitudes para respetar el rate limit
            time.sleep(1.5)
            
            url = f"{self.BASE_URL}/breachedaccount/{email}?truncateResponse=false"
            response = requests.get(url, headers=self.headers)
            
            if response.status_code == 200:
                return {
                    'email': email,
                    'breached': True,
                    'details': response.json()
                }
            elif response.status_code == 404:
                return {
                    'email': email,
                    'breached': False,
                    'details': None
                }
            else:
                return {
                    'email': email,
                    'breached': None,
                    'details': f"Error: Status code {response.status_code}"
                }
                
        except Exception as e:
            return {
                'email': email,
                'breached': None,
                'details': f"Error: {str(e)}"
            }

    def generate_report(self, results: List[Dict], output_file: str):
        """Genera un reporte detallado de los resultados."""
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            with open(output_file, 'w') as f:
                f.write("=== REPORTE DE ANÁLISIS DE BRECHAS DE SEGURIDAD ===\n")
                f.write(f"Fecha y hora: {timestamp}\n")
                f.write("=" * 50 + "\n\n")

                # Contador de correos comprometidos
                breached_count = sum(1 for r in results if r['breached'])
                total_count = len(results)
                
                f.write(f"Resumen:\n")
                f.write(f"- Total de correos analizados: {total_count}\n")
                f.write(f"- Correos comprometidos: {breached_count}\n")
                f.write(f"- Porcentaje comprometido: {(breached_count/total_count)*100:.2f}%\n\n")
                
                f.write("DETALLES DE CORREOS COMPROMETIDOS:\n")
                f.write("=" * 50 + "\n\n")
                
                for result in results:
                    if result['breached']:
                        f.write(f"Correo: {result['email']}\n")
                        f.write("-" * 30 + "\n")
                        
                        for breach in result['details']:
                            f.write(f"Brecha: {breach['Name']}\n")
                            f.write(f"Fecha: {breach['BreachDate']}\n")
                            f.write(f"Descripción: {breach['Description']}\n")
                            f.write(f"Datos comprometidos: {', '.join(breach['DataClasses'])}\n")
                            f.write("-" * 30 + "\n")
                        f.write("\n")
                
                f.write("\nCORREOS NO COMPROMETIDOS:\n")
                f.write("=" * 50 + "\n")
                for result in results:
                    if not result['breached']:
                        f.write(f"- {result['email']}\n")
                        
            print(f"Reporte generado exitosamente: {output_file}")
            
        except Exception as e:
            raise Exception(f"Error al generar el reporte: {str(e)}")

def main():
    # Configuración de archivos
    INPUT_FILE = "emails.txt"        # Archivo con lista de correos
    OUTPUT_FILE = "breach_report.txt" # Archivo donde se guardará el reporte
    
    try:
        analyzer = BreachAnalyzer()
        
        # Leer correos del archivo
        print("Leyendo archivo de correos...")
        emails = analyzer.read_emails(INPUT_FILE)
        print(f"Se encontraron {len(emails)} correos para analizar.")
        
        # Analizar cada correo
        print("Analizando correos...")
        results = []
        for i, email in enumerate(emails, 1):
            print(f"Analizando correo {i}/{len(emails)}: {email}")
            result = analyzer.check_breach(email)
            results.append(result)
        
        # Generar reporte
        print("Generando reporte...")
        analyzer.generate_report(results, OUTPUT_FILE)
        
    except Exception as e:
        print(f"Error durante la ejecución: {str(e)}")
        exit(1)

if __name__ == "__main__":
    main() 