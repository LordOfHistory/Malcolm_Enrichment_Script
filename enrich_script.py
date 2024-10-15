import requests
from requests.auth import HTTPBasicAuth
import logging
import configparser
from get_device_data import get_hostname, get_mdns_services
from get_device_data import get_tcp_syn_signatures, get_tcp_syn_ack_signatures, get_user_agent
from get_device_data import get_dhcp_fingerprint, get_dhcpv6_fingerprint, get_ja3_fingerprints, get_ja3_data
from get_device_data import get_destination_hosts, get_dhcp_vendor


# Función para obtener el token CSRF
def obtener_csrf_token():
    login_url = f"https://{config['GENERAL']['MALCOLM_IP']}/netbox/login/"
    session.get(login_url, auth=HTTPBasicAuth(config['NGINX']['USER'], config['NGINX']['PASSWORD']), verify=False)
    csrf_token = session.cookies.get('csrftoken')
    return csrf_token

# Función para comprobar si el dispositivo tiene la etiqueta "Enriquecido"
def is_enriched(device_id, tag = "enriquecido"):
    dispositivo_url = f"{NETBOX_URL}/dcim/devices/{device_id}/"
    response = session.get(dispositivo_url, headers=headers, auth=HTTPBasicAuth(config['NGINX']['USER'], config['NGINX']['PASSWORD']), verify=False)
    
    if response.status_code == 200:
        dispositivo_data = response.json()
        etiquetas_actuales = dispositivo_data.get("tags", [])
        # Comprobar si alguna etiqueta tiene el slug "enriquecido"
        tiene_enriquecido = any(etiqueta["slug"] == tag for etiqueta in etiquetas_actuales)
        return tiene_enriquecido
    else:
        logger.warning(f"Error al obtener los datos del dispositivo: {response.status_code}")
    
# Función para obtener la dirección MAC de un dispositivo
def obtener_mac_dispositivo(device_id):
    interfaces_url = f"{NETBOX_URL}/dcim/interfaces/?device_id={device_id}"
    response = session.get(interfaces_url, headers=headers, auth=HTTPBasicAuth(config['NGINX']['USER'], config['NGINX']['PASSWORD']), verify=False)

    if response.status_code == 200:
        data = response.json()
        interfaces = data.get('results', [])
        # Buscar la primera interfaz con una dirección MAC válida
        for interfaz in interfaces:
            mac_address = interfaz.get('mac_address')
            if mac_address:
                return mac_address
    else:
        logger.warning(f"Error al obtener las interfaces para el dispositivo {device_id}: {response.status_code} - {response.text}")

    return None

# Función para obtener la lista de dispositivos, sus IPs y MACs
def obtener_dispositivos_ips_y_macs(num=-1):
    lista_disp = []
    dispositivos_url = f"{NETBOX_URL}/dcim/devices/"
    siguiente_pagina = dispositivos_url
    control = False
    if num > 0:
        control = True

    while siguiente_pagina:
        response = session.get(siguiente_pagina, headers=headers, auth=HTTPBasicAuth(config['NGINX']['USER'], config['NGINX']['PASSWORD']), verify=False)

        if response.status_code == 200:
            data = response.json()
            dispositivos = data.get('results', [])

            # Procesar los dispositivos en la página actual
            for dispositivo in dispositivos:
                nombre = dispositivo.get('name', 'Desconocido')
                direccion_ip = dispositivo.get('primary_ip', {}).get('address', 'No especificada')
                dispositivo_id = dispositivo.get('id')
                direccion_mac = obtener_mac_dispositivo(dispositivo_id)
                ip, mascara = direccion_ip.split('/')
                enriched = is_enriched(dispositivo_id)
                fingerbanked = is_enriched(dispositivo_id,"fingerbank")
                if not enriched or not fingerbanked:
                    lista_disp.append({'id':dispositivo_id,'nombre':nombre,'ip':ip,'mac':direccion_mac,'enriched':enriched,'fingerbanked':fingerbanked})
                logger.info(f"Dispositivo: {nombre}, IP: {ip}, MAC: {direccion_mac}")
                if len(lista_disp)>=num and control:
                    break

            # Obtener la siguiente página
            siguiente_pagina = data.get('next')
        else:
            logger.warning(f"Error al obtener los dispositivos: {response.status_code} - {response.text}")
            break
        if len(lista_disp)>=num and control:
            break
    return lista_disp

# Función para realizar el análisis basado en la IP y MAC proporcionadas
def run_analysis(ip, mac=None):
    result = {}
    logger.info(f"Iniciando análisis para IP: {ip} y MAC: {mac}")

    # Llamada a la función mdns_services
    logger.info("Ejecutando análisis de servicios mDNS")
    mdns_services = get_mdns_services(ip)
    result["mdns_services"] = mdns_services if mdns_services else None
    logger.info(f"Servicios mDNS: {mdns_services}")

    # Llamada a la función tcp_syn_signatures
    logger.info("Ejecutando análisis de firmas TCP SYN")
    tcp_syn_signatures = get_tcp_syn_signatures(ip)
    result["tcp_syn_signatures"] = tcp_syn_signatures if tcp_syn_signatures else None
    logger.info(f"Firmas TCP SYN: {tcp_syn_signatures}")

    # Llamada a la función tcp_syn_ack_signatures
    logger.info("Ejecutando análisis de firmas TCP SYN-ACK")
    tcp_syn_ack_signatures = get_tcp_syn_ack_signatures(ip)
    result["tcp_syn_ack_signatures"] = tcp_syn_ack_signatures if tcp_syn_ack_signatures else None
    logger.info(f"Firmas TCP SYN-ACK: {tcp_syn_ack_signatures}")

    # Llamada a la función user_agents
    logger.info("Ejecutando análisis de agentes de usuario")
    user_agents = get_user_agent(ip)
    result["user_agents"] = user_agents if user_agents else None
    logger.info(f"Agentes de usuario: {user_agents}")

    # Llamada a las funciones que requieren el parámetro mac si mac es válido
    if mac and mac!="FF:FF:FF:FF:FF:FF":
        # Llamada a la función DHCP fingerprint
        logger.info("Ejecutando análisis de huella digital DHCP")
        dhcp_fingerprint = get_dhcp_fingerprint(mac)
        result["dhcp_fingerprint"] = dhcp_fingerprint if dhcp_fingerprint else None
        logger.info(f"Huellas digitales DHCP: {dhcp_fingerprint}")

        # Llamada a la función DHCP vendor
        logger.info("Ejecutando análisis de vendor DHCP")
        dhcp_vendor = get_dhcp_vendor(mac)
        result["dhcp_vendor"] = dhcp_vendor if dhcp_vendor else None
        logger.info(f"Vendor DHCP: {dhcp_vendor}")

        # Llamada a la función DHCPv6 fingerprint
        logger.info("Ejecutando análisis de huella digital DHCPv6")
        dhcpv6_fingerprint = get_dhcpv6_fingerprint(mac)
        result["dhcpv6_fingerprint"] = dhcpv6_fingerprint if dhcpv6_fingerprint else None
        logger.info(f"Huellas digitales DHCPv6: {dhcpv6_fingerprint}")
    else:
        logger.info("No se proporcionó una dirección MAC válida, omitiendo análisis relacionados con DHCP.")
        result["dhcp_fingerprint"] = None
        result["dhcp_vendor"] = None
        result["dhcpv6_fingerprint"] = None


    # Llamada a la función JA3 fingerprint
    logger.info("Ejecutando análisis de huella digital JA3")
    ja3_fingerprints = get_ja3_fingerprints(ip)
    result["ja3_fingerprints"] = ja3_fingerprints if ja3_fingerprints else None
    logger.info(f"Huellas digitales JA3: {ja3_fingerprints}")

    # Llamada a la función JA3 data
    logger.info("Ejecutando análisis de datos JA3")
    ja3_data = get_ja3_data(ip)
    result["ja3_data"] = ja3_data if ja3_data else None
    logger.info(f"Datos JA3: {ja3_data}")

    # Llamada a la función de destinos (destination hosts)
    logger.info("Ejecutando análisis de hosts de destino")
    destination_hosts = get_destination_hosts(ip)
    result["destination_hosts"] = destination_hosts if destination_hosts else None
    logger.info(f"Hosts de destino: {destination_hosts}")

    # Llamada a la función de hostname
    logger.info("Ejecutando análisis de nombre de host")
    hostname = get_hostname(ip)
    result["hostname"] = hostname if hostname!=ip else None
    logger.info(f"Nombre de host: {hostname}")

    return result

def consultar_fingerbank(mac, dhcp_fingerprint=None, dhcp_vendor=None, dhcpv6_fingerprint=None, user_agent=None, 
                         mdns_services=None, tcp_syn_signatures=None, tcp_syn_ack_signatures=None,
                         ja3_fingerprints=None, ja3_data=None, hostname=None, destination_hosts=None):
    logger.info("Consultando Fingerbank con los datos disponibles")

    # Parámetros para la consulta a Fingerbank
    params = {
        "mac": mac,
        "key": config["FINGERBANK"]["TOKEN"]  # Tu token Fingerbank
    }

    if dhcp_fingerprint:
        params['dhcp_fingerprint'] = dhcp_fingerprint
    if dhcp_vendor:
        params['dhcp_vendor'] = dhcp_vendor
    if dhcpv6_fingerprint:
        params['dhcpv6_fingerprint'] = ','.join(map(str, dhcpv6_fingerprint))  # Convertir lista a string
    if user_agent:
        params['user_agent'] = user_agent
    if mdns_services:
        params['mdns'] = ','.join(mdns_services)  # Convertir lista a string
    if tcp_syn_signatures:
        params['tcp_syn'] = ','.join(map(str, tcp_syn_signatures))
    if tcp_syn_ack_signatures:
        params['tcp_syn_ack'] = ','.join(map(str, tcp_syn_ack_signatures))
    if ja3_fingerprints:
        params['ja3'] = ','.join(ja3_fingerprints)
    if ja3_data:
        params['ja3_data'] = str(ja3_data)
    if hostname:
        params['hostname'] = hostname
    if destination_hosts:
        params['destination_hosts'] = destination_hosts

    # Realizar la solicitud a Fingerbank
    FINGERBANK_API_URL = "https://api.fingerbank.org/api/v2/combinations/interrogate"
    logger.info(f"Parámetros enviados a Fingerbank: {params}")
    response = requests.get(FINGERBANK_API_URL, params=params)

    if response.status_code == 200:
        data = response.json()
        logger.info(f"Respuesta de Fingerbank: {data}")
        return data
    else:
        logger.error(f"Error consultando Fingerbank: {response.status_code} - {response.text}")
        return None

# Función para agregar la etiqueta "Fingerbank" si no está presente y actualizar Datos de contexto
def write_data(dispositivo_id, datos_contexto=None):
    dispositivo_url = f"{NETBOX_URL}/dcim/devices/{dispositivo_id}/"
    
    # Obtener los datos actuales del dispositivo para verificar las etiquetas
    response = session.get(dispositivo_url, headers=headers, auth=HTTPBasicAuth(config['NGINX']['USER'], config['NGINX']['PASSWORD']), verify=False)
    if response.status_code != 200:
        logger.warning(f"Error al obtener los datos del dispositivo: {response.status_code} - {response.text}")
        return
    
    dispositivo_data = response.json()
    etiquetas_actuales = dispositivo_data.get("tags", [])

    # Comprobar si la etiqueta "Fingerbank" está presente en las etiquetas actuales
    fingerbanked = any(etiqueta["slug"] == "fingerbank" for etiqueta in etiquetas_actuales)
    enriched = any(etiqueta["slug"] == "enriquecido" for etiqueta in etiquetas_actuales)
    logger.debug(f"Etiquetas actuales del dispositivo: {etiquetas_actuales}")

    
        # Obtener el ID de la etiqueta "Fingerbank"
    if not fingerbanked and datos_contexto["fingerbanked"]==True:
        etiquetas_url = f"{NETBOX_URL}/extras/tags/?slug=fingerbank"
        response = session.get(etiquetas_url, headers=headers, auth=HTTPBasicAuth(config['NGINX']['USER'], config['NGINX']['PASSWORD']), verify=False)
        
        if response.status_code == 200:
            data = response.json()
            fingerbank_tag = data.get("results", [])[0]
            fingerbank_id = fingerbank_tag["id"]
            etiquetas_actuales.append({"id": fingerbank_id})
        else:
            print(f"Error al obtener la etiqueta 'Fingerbank': {response.status_code} - {response.text}")

    if not enriched:
        etiquetas_url = f"{NETBOX_URL}/extras/tags/?slug=enriquecido"
        response = session.get(etiquetas_url, headers=headers, auth=HTTPBasicAuth(config['NGINX']['USER'], config['NGINX']['PASSWORD']), verify=False)
        
        if response.status_code == 200:
            data = response.json()
            enriquecido_tag = data.get("results", [])[0]
            enriquecido_id = enriquecido_tag["id"]
            etiquetas_actuales.append({"id": enriquecido_id})
        else:
            print(f"Error al obtener la etiqueta 'Fingerbank': {response.status_code} - {response.text}")

    # Agregar la etiqueta "Fingerbank" y actualizar Datos de contexto
    update_data = {
        "local_context_data": datos_contexto,
        "tags": [etiqueta["id"] for etiqueta in etiquetas_actuales]
    }

    # Realizar la solicitud PATCH para actualizar el dispositivo
    response = session.patch(dispositivo_url, headers=headers, json=update_data, auth=HTTPBasicAuth(config['NGINX']['USER'], config['NGINX']['PASSWORD']), verify=False)

    if response.status_code == 200:
        logger.info(f"Etiqueta 'Fingerbank' añadida y Datos de contexto actualizados para el dispositivo con ID {dispositivo_id}.")
    else:
        logger.warning(f"Error al actualizar el dispositivo: {response.status_code} - {response.text}")



if __name__ == "__main__":
    # Obtener el token CSRF
    config = configparser.ConfigParser()
    config.read('config.ini')
    logger = logging.getLogger(__name__)
    logging.basicConfig(level=(int(config['GENERAL']['LOG_LEVEL'])*10))
    headers = {"Content-Type": "application/json"}
    auth=HTTPBasicAuth(config['NGINX']['USER'], config['NGINX']['PASSWORD'])
    # URL de la API de NetBox
    NETBOX_URL = f"https://{config['GENERAL']['MALCOLM_IP']}/netbox/api"
    # Configurar la sesión y los encabezados
    session = requests.Session()
    csrf_token = obtener_csrf_token()
    headers = {
        "Authorization": f"Token {config['NETBOX']['TOKEN']}",
        "X-CSRFToken": csrf_token,
        "Content-Type": "application/json",
        "Referer": f"https://{config['GENERAL']['MALCOLM_IP']}/netbox/",
    }
    # Desactivar advertencias de SSL
    requests.packages.urllib3.disable_warnings()



    # Ejecutar la función para obtener las IPs y MACs de todos los dispositivos
    list_assets = obtener_dispositivos_ips_y_macs(int(config['ENRICHMENT']['BATCH_SIZE']))

    for asset in list_assets:
        print (asset)
        asset["enrichment_data"]=run_analysis(asset["ip"],asset["mac"])
        asset["enriched"] = True

    
    for asset in list_assets:
        asset["fingerbank_data"]=consultar_fingerbank(asset["mac"], asset["enrichment_data"]["dhcp_fingerprint"],
                             asset["enrichment_data"]["dhcp_vendor"], asset["enrichment_data"]["dhcpv6_fingerprint"], 
                             asset["enrichment_data"]["user_agents"], asset["enrichment_data"]["mdns_services"], 
                             asset["enrichment_data"]["tcp_syn_signatures"], asset["enrichment_data"]["tcp_syn_ack_signatures"], 
                             asset["enrichment_data"]["ja3_fingerprints"], asset["enrichment_data"]["ja3_data"], 
                             asset["enrichment_data"]["hostname"], asset["enrichment_data"]["destination_hosts"])
        if asset["fingerbank_data"] is not None:
            asset["fingerbanked"] = True

    for asset in list_assets:
        write_data(asset["id"], asset)
        logger.info (asset)
