import requests
from requests.auth import HTTPBasicAuth

# URL de la API de NetBox
NETBOX_URL = "https://10.14.1.150/netbox"
API_URL = f"{NETBOX_URL}/api"
API_TOKEN = "0bd7ccd362455053ccc44971ad2e3b2c31168e55"
NGINX_USER = "analyst"
NGINX_PASSWORD = "M!G4ever"

# Crear una sesión para manejar cookies
session = requests.Session()

# Desactivar advertencias de SSL
requests.packages.urllib3.disable_warnings()

# Función para obtener el token CSRF
def obtener_csrf_token():
    login_url = f"{NETBOX_URL}/login/"
    session.get(login_url, auth=HTTPBasicAuth(NGINX_USER, NGINX_PASSWORD), verify=False)
    csrf_token = session.cookies.get('csrftoken')
    return csrf_token

# Obtener el token CSRF
csrf_token = obtener_csrf_token()

# Añadir encabezados de autorización y CSRF
headers = {
    "Authorization": f"Token {API_TOKEN}",
    "X-CSRFToken": csrf_token,
    "Content-Type": "application/json",
    "Referer": NETBOX_URL,
}

# Función para obtener todos los dispositivos
def obtener_todos_los_dispositivos():
    dispositivos_url = f"{API_URL}/dcim/devices/"
    siguiente_pagina = dispositivos_url
    dispositivos = []

    while siguiente_pagina:
        response = session.get(siguiente_pagina, headers=headers, auth=HTTPBasicAuth(NGINX_USER, NGINX_PASSWORD), verify=False)

        if response.status_code == 200:
            data = response.json()
            dispositivos.extend(data.get('results', []))
            siguiente_pagina = data.get('next')  # Obtener la siguiente página si existe
        else:
            print(f"Error al obtener los dispositivos: {response.status_code} - {response.text}")
            break

    return dispositivos

# Función para eliminar las etiquetas "enriquecido" y "fingerbank" de un dispositivo
def eliminar_etiquetas(dispositivo):
    dispositivo_id = dispositivo.get('id')
    dispositivo_url = f"{API_URL}/dcim/devices/{dispositivo_id}/"

    # Obtener los datos actuales del dispositivo
    response = session.get(dispositivo_url, headers=headers, auth=HTTPBasicAuth(NGINX_USER, NGINX_PASSWORD), verify=False)
    
    if response.status_code != 200:
        print(f"Error al obtener los datos del dispositivo {dispositivo.get('name')}: {response.status_code} - {response.text}")
        return

    dispositivo_data = response.json()
    etiquetas_actuales = dispositivo_data.get("tags", [])

    # Filtrar las etiquetas "enriquecido" y "fingerbank"
    nuevas_etiquetas = [etiqueta for etiqueta in etiquetas_actuales if etiqueta["slug"] not in ["enriquecido", "fingerbank"]]

    # Si las etiquetas han cambiado, actualiza el dispositivo
    if len(etiquetas_actuales) != len(nuevas_etiquetas):
        update_data = {
            "tags": [etiqueta["id"] for etiqueta in nuevas_etiquetas]
        }

        # Realizar la solicitud PATCH para actualizar el dispositivo
        response = session.patch(dispositivo_url, headers=headers, json=update_data, auth=HTTPBasicAuth(NGINX_USER, NGINX_PASSWORD), verify=False)

        if response.status_code == 200:
            print(f"Se eliminaron las etiquetas de 'enriquecido' y 'fingerbank' para el dispositivo {dispositivo.get('name')}.")
        else:
            print(f"Error al actualizar las etiquetas del dispositivo {dispositivo.get('name')}: {response.status_code} - {response.text}")
    else:
        print(f"El dispositivo {dispositivo.get('name')} no tiene etiquetas 'enriquecido' o 'fingerbank'.")

# Función principal para recorrer y eliminar etiquetas
def main():
    dispositivos = obtener_todos_los_dispositivos()

    if dispositivos:
        for dispositivo in dispositivos:
            eliminar_etiquetas(dispositivo)
    else:
        print("No se encontraron dispositivos para procesar.")

# Ejecutar el script
if __name__ == "__main__":
    main()
