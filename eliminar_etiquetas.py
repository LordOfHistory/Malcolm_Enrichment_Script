from enrichment_lib import *

# Ejecutar el script
if __name__ == "__main__":
    dispositivos = obtener_todos_los_dispositivos()
    if dispositivos:
        for dispositivo in dispositivos:
            eliminar_etiquetas(dispositivo)
    else:
        print("No se encontraron dispositivos para procesar.")
