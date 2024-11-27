import openpyxl

def procesar_controles(archivo_xlsx, codigos_entrada):
  wb = openpyxl.load_workbook(archivo_xlsx)
  sheet = wb.active

  controles = {}
  for row in sheet.iter_rows(min_row=2, values_only=True):
      codigo, nombre, tipo = row
      controles[str(codigo)] = (nombre, tipo)

  preventivos_total = 0
  correctivos_total = 0
  preventivos_aplicados = 0
  correctivos_aplicados = 0
  controles_encontrados = []

  for codigo in codigos_entrada:
      if codigo in controles:
          nombre, tipo = controles[codigo]
          aplicado = preguntar_si_aplicado(codigo, nombre)
          controles_encontrados.append((codigo, nombre, tipo, aplicado))

          if tipo.lower() == 'preventivo':
              preventivos_total += 1
              if aplicado:
                  preventivos_aplicados += 1
          elif tipo.lower() == 'correctivo':
              correctivos_total += 1
              if aplicado:
                  correctivos_aplicados += 1

  return preventivos_aplicados, correctivos_aplicados, preventivos_total, correctivos_total, controles_encontrados

def obtener_codigos_usuario():
  codigos = []
  print("Ingrese los códigos (presione Enter sin ingresar nada para terminar):")
  while True:
      entrada = input("Código: ")
      if entrada == "":
          break
      try:
          # Verificar si la entrada es un número válido, pero mantenerla como string
          float(entrada)  # Esto lanzará ValueError si no es un número válido
          codigos.append(entrada)
      except ValueError:
          print("Por favor, ingrese un número válido.")
  return codigos

def obtener_valor_numerico(mensaje):
    while True:
        try:
            valor = float(input(mensaje))
            return valor
        except ValueError:
            print("Por favor, ingrese un número válido.")

def ajustar_valor(valor, porcentaje):
  if 1 <= porcentaje <= 30:
      valor -= 1
  elif 31 <= porcentaje <= 70:
      valor -= 2
  elif 71 <= porcentaje <= 100:
      valor = 0
  return max(0, valor)

def preguntar_si_aplicado(codigo, nombre):
  while True:
      respuesta = input(f"¿El control '{codigo} - {nombre}' ha sido aplicado? (si/no): ").lower()
      if respuesta in ['si', 'sí', 's', 'yes', 'y']:
          return True
      elif respuesta in ['no', 'n']:
          return False
      else:
          print("Por favor, responda 'si' o 'no'.")

# Ejemplo de uso3
archivo_xlsx = 'controls_iso27002.xlsx'

probabilidad = obtener_valor_numerico("Ingrese el valor de probabilidad: ")
impacto = obtener_valor_numerico("Ingrese el valor de impacto: ")

codigos_entrada = obtener_codigos_usuario()

preventivos_aplicados, correctivos_aplicados, preventivos_total, correctivos_total, controles_encontrados = procesar_controles(archivo_xlsx, codigos_entrada)

porcentaje_preventivos = (preventivos_aplicados / preventivos_total * 100) if preventivos_total > 0 else 0
porcentaje_correctivos = (correctivos_aplicados / correctivos_total * 100) if correctivos_total > 0 else 0

#print(f"\nCódigos ingresados: {codigos_entrada}")

print("\nControles encontrados:")
for codigo, nombre, tipo, aplicado in controles_encontrados:
  estado = "Aplicado" if aplicado else "No aplicado"
  print(f"Código: {codigo}, Nombre: {nombre}, Tipo: {tipo}, Estado: {estado}")

print(f"\nControles preventivos: {preventivos_aplicados} aplicados de {preventivos_total} ({porcentaje_preventivos:.2f}%)")
print(f"Controles correctivos: {correctivos_aplicados} aplicados de {correctivos_total} ({porcentaje_correctivos:.2f}%)")

nueva_probabilidad = ajustar_valor(probabilidad, porcentaje_preventivos)
nuevo_impacto = ajustar_valor(impacto, porcentaje_correctivos)

riesgo_original = probabilidad * impacto
riesgo_nuevo = nueva_probabilidad * nuevo_impacto

if riesgo_original > 0:
  porcentaje_mitigacion = ((riesgo_original - riesgo_nuevo) / riesgo_original) * 100
else:
  porcentaje_mitigacion = 0

#print(f"\nProbabilidad original: {probabilidad}")
print(f"Nueva probabilidad: {nueva_probabilidad}")
#print(f"Impacto original: {impacto}")
print(f"Nuevo impacto: {nuevo_impacto}")
#print(f"Riesgo original: {riesgo_original}")
print(f"Riesgo nuevo: {riesgo_nuevo}")
print(f"Porcentaje de mitigación del riesgo a ingresar en SIMPLERISK: {porcentaje_mitigacion:.2f}%")

# Created/Modified files during execution:
# None