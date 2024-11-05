import requests
import logging
import configparser
from requests.auth import HTTPBasicAuth
import warnings
import os
from urllib3.exceptions import InsecureRequestWarning
import scapy.all as scapy
from scapy.all import rdpcap, DHCP
import ipaddress
import socket
import pyshark
from io import BytesIO
from elasticsearch import Elasticsearch
import json

# Importamos la configuración
config = configparser.ConfigParser()
config.read('config.ini')

# Configuramos el logger
logger = logging.getLogger(__name__)
logging.basicConfig(level=(int(config['GENERAL']['LOG_LEVEL'])*10))

# Deshabilitamos los warnings
requests.packages.urllib3.disable_warnings()
warnings.simplefilter('ignore', InsecureRequestWarning)

# Preparamos los headers y auth por defecto
session = requests.Session()   
headers = {"Content-Type": "application/json"}
auth=HTTPBasicAuth(config['NGINX']['USER'], config['NGINX']['PASSWORD'])

#############################################################################################
# Funciones de enriquecimiento
#############################################################################################
#TODO: Terminar esta función
def get_client_hints(ip):
    logger.info("SEARCHING CLIENT HINTS FOR "+ ip)
    packets = get_real_pcaps(f"ip.dst == {ip} && protocols == http")
    client_hints=None
    if packets != None:
        for packet in packets:
            if packet.haslayer(scapy.Raw):
                #TODO: Pendiente de encontrar PCAPS con client hints
                """ raw_data = packet[scapy.Raw].load.decode(errors="ignore")
                if "User-Agent:" in raw_data:
                    for line in raw_data.splitlines():
                        if line.startswith("User-Agent:"):
                            user_agent = line.split("User-Agent:")[1].strip()
                            break
                    logger.info(f"User-Agent detectado: {user_agent}") """
            if client_hints is not None:
                break
    return client_hints   

def get_dhcp_fingerprint(mac):
    logger.info("SEARCHING DHCP FINGERPRINT FOR "+ mac)
    packets = get_real_pcaps(f"mac.src == {mac} && protocols == dhcp")    
    dhcp_fingerprint=None
    if packets != None:
        for packet in packets:
            if packet.haslayer(DHCP):
                dhcp_options = packet[DHCP].options
                for option in dhcp_options:
                    if option[0] == 'param_req_list':
                        dhcp_fingerprint = option[1]  # Guarda el valor
                        break  # Salir del bucle si lo encuentra
            if dhcp_fingerprint is not None:
                logger.info (f"Found dhcp fingerprint, retuning value {dhcp_fingerprint}")
                break
    return dhcp_fingerprint

def get_dhcpv6_fingerprint(mac):
    logger.info("SEARCHING DHCPv6 FINGERPRINT FOR "+ mac)
    packets = get_real_pcaps(f"mac.src == {mac} && protocols == dhcpv6")
    dhcpv6_fingerprint = None
    if packets != None:
        for packet in packets:
            dhcpv6_packet = None
            if packet.haslayer(scapy.DHCP6_Solicit):
                #print("Este es un paquete DHCPv6 Solicit.")
                dhcpv6_packet = packet[scapy.DHCP6_Solicit]
            
            elif packet.haslayer(scapy.DHCP6_Advertise):
                #print("Este es un paquete DHCPv6 Advertise.")
                dhcpv6_packet = packet[scapy.DHCP6_Advertise]
            
            elif packet.haslayer(scapy.DHCP6_Request):
                #print("Este es un paquete DHCPv6 Request.")
                dhcpv6_packet = packet[scapy.DHCP6_Request]

            elif packet.haslayer(scapy.DHCP6_Reply):
                #print("Este es un paquete DHCPv6 Reply.")
                dhcpv6_packet = packet[scapy.DHCP6_Reply]
            
            elif packet.haslayer(scapy.DHCP6_Release):
                #print("Este es un paquete DHCPv6 Release.")
                dhcpv6_packet = packet[scapy.DHCP6_Release]
            
            if dhcpv6_packet is not None:
                opt_req_layer = dhcpv6_packet.getlayer(scapy.DHCP6OptOptReq)
                if opt_req_layer is not None:
                    dhcpv6_fingerprint = opt_req_layer.reqopts
                    logger.info (f"Found dhcpv6 fingerprint, retuning value {dhcpv6_fingerprint}")
                    break
    return dhcpv6_fingerprint           
#TODO: Revisar y probar con pcaps
def get_dhcpv6_enterprise(mac):
    logger.info("SEARCHING DHCPv6 ENTERPRISE FOR "+ mac)
    packets = get_real_pcaps(f"mac.src == {mac} && protocols == dhcpv6")
    dhcpv6_enterprise = None
    if packets != None:
            for packet in packets:
                dhcpv6_packet = None
                if packet.haslayer(scapy.DHCP6_Solicit):
                    #print("Este es un paquete DHCPv6 Solicit.")
                    dhcpv6_packet = packet[scapy.DHCP6_Solicit]
                
                elif packet.haslayer(scapy.DHCP6_Advertise):
                    #print("Este es un paquete DHCPv6 Advertise.")
                    dhcpv6_packet = packet[scapy.DHCP6_Advertise]
                
                elif packet.haslayer(scapy.DHCP6_Request):
                    #print("Este es un paquete DHCPv6 Request.")
                    dhcpv6_packet = packet[scapy.DHCP6_Request]

                elif packet.haslayer(scapy.DHCP6_Reply):
                    #print("Este es un paquete DHCPv6 Reply.")
                    dhcpv6_packet = packet[scapy.DHCP6_Reply]
                
                elif packet.haslayer(scapy.DHCP6_Release):
                    #print("Este es un paquete DHCPv6 Release.")
                    dhcpv6_packet = packet[scapy.DHCP6_Release]
                
                if dhcpv6_packet is not None:
                    #TODO: Completar recuperación cuando tengamos paquetes DHCPv6 con enterprise
                    """ opt_req_layer = dhcpv6_packet.getlayer(scapy.DHCP6OptOptReq)
                    if opt_req_layer is not None:
                        dhcpv6_enterprise = opt_req_layer.reqopts
                        logger.info (f"Found dhcpv6 enterprise, retuning value {dhcpv6_enterprise}")
                        break """
                    logger.info("No DHCPv6 enterprise found")
    return dhcpv6_enterprise           
#TODO: Revisar y probar con pcaps
def get_dhcp_vendor(mac):
    logger.info("SEARCHING DHCP VENDOR FOR "+ mac)
    packets = get_real_pcaps(f"mac.src == {mac} && protocols == dhcp")
    dhcp_vendor=None
    if packets != None:
        for packet in packets:
            if packet.haslayer(DHCP):
                dhcp_options = packet[DHCP].options
                for option in dhcp_options:
                    if option[0] == 'vendor':
                        dhcp_vendor = option[1]  # Guarda el valor
                        logger.info (f"Found dhcp vendor, retuning value {dhcp_vendor}")
                        break  # Salir del bucle si lo encuentra
            if dhcp_vendor is not None:
                break  # Salir del bucle principal si se e
    return dhcp_vendor

def get_user_agent(ip):
    logger.info("SEARCHING USER AGENT FOR "+ ip)
    packets = get_real_pcaps(f"ip.src == {ip} && protocols == http")
    user_agent=None
    if packets != None:
        for packet in packets:
            if packet.haslayer(scapy.Raw):
                raw_data = packet[scapy.Raw].load.decode(errors="ignore")
                if "User-Agent:" in raw_data:
                    for line in raw_data.splitlines():
                        if line.startswith("User-Agent:"):
                            user_agent = line.split("User-Agent:")[1].strip()
                            logger.info(f"User-Agent detectado: {user_agent}")
                            break
            if user_agent is not None:
                break
    return user_agent

def get_destination_hosts(ip):
    malcolm_ip = config['GENERAL']['MALCOLM_IP']

    # Variables para la paginación
    related_ips = set()  # Usar un conjunto para evitar duplicados
    start = 0
    length = 50  # Reducir el número de sesiones por página
    max_pages = 5  # Limitar el número de iteraciones para evitar bucles infinitos

    logger.info("SEARCHING DESTINATION HOSTS FOR "+ ip)
    for _ in range(max_pages):
        # Realizar una solicitud GET a la API de Arkime para obtener las sesiones con la IP dada
        expression = f'ip.src == {ip} || ip.dst == {ip}'
        try:
            response = requests.get(
                f"https://{malcolm_ip}/arkime/api/sessions?expression={expression}&start={start}&length={length}",
                headers=headers,
                auth=auth,
                verify=False,
                timeout=10  # Establecer un tiempo máximo de espera de 10 segundos por solicitud
            )
        except requests.exceptions.RequestException as e:
            logger.info(f"Request failed: {e}")
            return []

        # Si hay un error, detener y devolver un resultado vacío
        if response.status_code != 200:
            logger.info(f"Error fetching sessions: {response.status_code} - {response.text}")
            return []

        # Procesar la respuesta si es exitosa
        response_data = response.json()
        sessions = response_data.get('data', [])
        
        # Revisar las sesiones y extraer las direcciones IP de origen y destino
        for session in sessions:
            source_ip = session.get('source', {}).get('ip')
            destination_ip = session.get('destination', {}).get('ip')

            # Agregar IP de origen si es diferente a la IP proporcionada
            if source_ip and source_ip != ip:
                related_ips.add(source_ip)

            # Agregar IP de destino si es diferente a la IP proporcionada
            if destination_ip and destination_ip != ip:
                related_ips.add(destination_ip)

        # Si el número de sesiones recuperadas es menor que `length`, significa que no hay más sesiones
        if len(sessions) < length:
            break

        # Actualizar `start` para obtener la siguiente página de resultados
        start += length

    # Limitar los elementos a 5 si hay más de 5
    related_ips_list = list(related_ips)
    if len(related_ips_list) > 5:
        related_ips_list = related_ips_list[:5]

    # Clasificar las IPs en públicas y resolver los dominios
    domains = []

    for related_ip in related_ips_list:
        if not ipaddress.ip_address(related_ip).is_private:
            try:
                domain = socket.gethostbyaddr(related_ip)[0]
                domains.append(domain)
            except socket.herror:
                # Ignorar si no se encuentra el dominio
                continue
    logger.info(f"Destination hosts detected: {domains}")
    return domains

def get_hostname(ip):
    logger.debug("SEARCHING HOSTNAME FOR "+ ip)
    hostname = ip
    if not ipaddress.ip_address(ip).is_private:
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            if hostname:
                logger.debug("Found public hostname: "+hostname)
        except socket.herror:
            logger.debug("Domain for this IP not found publicly")
    return hostname

def get_ja3_fingerprints(ip):
    logger.info("SEARCHING JA3 FINGERPRINT FOR "+ ip)
    cap = get_real_pcaps(f"ip == {ip} && protocols == tls","ja3.pcap")    
    ja3_fingerprint = []
    if cap != None:
        try:
            pkts = pyshark.FileCapture("ja3.pcap", display_filter=f"ip.addr == {ip} and tls.handshake")
            with pkts as capture:
                for pkt in capture:
                    if hasattr(pkt, 'tls'):
                        # Verificar si el paquete es un Client Hello o un Server Hello
                        if '1' in pkt.tls.handshake_type:  # Client Hello
                            # Mostrar solo si la IP de origen o destino coincide
                            if pkt.ip.src == ip or pkt.ip.dst == ip:
                                tls_layer = pkt.tls
                                if hasattr(tls_layer, 'handshake_ja3'):
                                    if tls_layer.handshake_ja3 not in ja3_fingerprint:
                                        ja3_fingerprint.append(tls_layer.handshake_ja3)
                                if len(ja3_fingerprint) >= 5:
                                    break
            os.remove("ja3.pcap")
        except Exception as e:
            logger.warning(f"Something failed procesing the pcap: {e}")
    logger.info(f"JA3 fingerprint: {ja3_fingerprint}")
    return ja3_fingerprint

def get_ja3_data(ip):
    logger.info("SEARCHING JA3 DATA FOR "+ ip)
    cap = get_real_pcaps(f"ip == {ip} && protocols == tls","ja3data.pcap")    
    ja3_data = {}
    grouped_data = None
    if cap != None:
        try:
            pkts = pyshark.FileCapture("ja3data.pcap", display_filter=f"ip.addr == {ip} and tls.handshake")
            for pkt in pkts:
                if hasattr(pkt, 'tls'):
                    tls_layer = pkt.tls
                    # Verificar si el paquete es un Client Hello o un Server Hello
                    if '1' in pkt.tls.handshake_type:  # Client Hello
                        # Mostrar solo si la IP de origen o destino coincide
                        if pkt.ip.src == ip or pkt.ip.dst == ip:
                            if hasattr(tls_layer, 'handshake_ja3'):
                                ja3_fingerprint = tls_layer.handshake_ja3
                                ip_pair = (f"{get_hostname(pkt.ip.src)}:{pkt[pkt.transport_layer].srcport}", f"{get_hostname(pkt.ip.dst)}:{pkt[pkt.transport_layer].dstport}")
                                # Almacenar el JA3 en el diccionario para el par de IPs y puerto destino
                                if ip_pair not in ja3_data:
                                    ja3_data[ip_pair] = {"ja3": ja3_fingerprint, "ja3s": None}
                                else:
                                    ja3_data[ip_pair]["ja3"] = ja3_fingerprint                           
                    elif '2' in pkt.tls.handshake_type:  # Server Hello
                    # Mostrar solo si la IP de origen o destino coincide
                        if pkt.ip.src == ip or pkt.ip.dst == ip:
                            if hasattr(tls_layer, 'handshake_ja3s'):
                                ja3s_fingerprint = tls_layer.handshake_ja3s
                                ip_pair = ( f"{get_hostname(pkt.ip.dst)}:{pkt[pkt.transport_layer].dstport}",f"{get_hostname(pkt.ip.src)}:{pkt[pkt.transport_layer].srcport}")  # Relación inversa para Server Hello, con puerto destino
                                # Almacenar el JA3S en el diccionario para el par de IPs y puerto destino
                                if ip_pair not in ja3_data:
                                    ja3_data[ip_pair] = {"ja3": None, "ja3s": ja3s_fingerprint}
                                else:
                                    ja3_data[ip_pair]["ja3s"] = ja3s_fingerprint
            grouped_data = {}
            for ip_pair, fingerprints in ja3_data.items():
                dst = ip_pair[1]
                ja3_ja3s_pair = f"{fingerprints['ja3']};{fingerprints['ja3s']}"
                if dst not in grouped_data:
                    grouped_data[dst] = []
                if "None" not in ja3_ja3s_pair and ja3_ja3s_pair not in grouped_data[dst]:
                    grouped_data[dst].append(ja3_ja3s_pair)
                if ja3_ja3s_pair not in grouped_data[dst]:
                    grouped_data[dst].append(ja3_ja3s_pair)
            pkts.close()
            os.remove("ja3data.pcap")
        except Exception as e:
            print(f"Something failed procesing the pcap: {e}")
    logger.info(f"JA3 data: {grouped_data}")
    return grouped_data

def get_mdns_services(ip):
    try:
        # Leer el archivo pcapng
        packets = get_real_pcaps(f"ip.src == {ip} && protocols == mdns")
        mdns_services = set()
        # Iterar sobre los paquetes y buscar paquetes mDNS
        if packets != None:
            for packet in packets:
                if packet.haslayer("DNS"):
                    # Filtrar por la IP de origen
                    if packet["IP"].src == ip:
                        # Buscar en la sección de consulta (qd) y en la sección de respuestas (an)
                        if packet["DNS"].qd:
                            query_name = packet["DNS"].qd.qname.decode()
                            if "_udp.local" in query_name or "_tcp.local" in query_name:
                                mdns_services.add(query_name)
                        if packet["DNS"].an:
                            for i in range(packet["DNS"].ancount):
                                answer_name = packet["DNS"].an[i].rrname.decode()
                                if "_udp.local" in answer_name or "_tcp.local" in answer_name:
                                    mdns_services.add(answer_name)
        return list(mdns_services)
    except Exception as e:
        logger.warning(f"Error reading pcapng file: {e}")
        return None

def get_tcp_syn_signatures(ip):
    filtro = f"ip.addr == {ip} and tcp.flags.syn == 1"
    
    # Cargar la captura de paquetes con el filtro
    cap = get_real_pcaps(f"ip == {ip} && protocols == tcp","tcp_syn.pcap")
    
    # Listas para guardar las firmas de los paquetes
    firmas_tcp = []
    if cap != None:
        try:
            cap = pyshark.FileCapture("tcp_syn.pcap", display_filter=filtro)
            for pkt in cap:
                ip_version = pkt.ip.version
                ttl = pkt.ip.ttl
                # Acceder a la capa TCP
                tcp_layer = pkt.tcp
                ip_layer = pkt.ip
                
                # MSS (Maximum Segment Size)
                mss = tcp_layer.get_field_value('tcp.option_mss_val') or '0'
                
                # Tamaño de la ventana TCP
                window_size = tcp_layer.window_size or '0'
                
                # Window Scale Factor
                window_scaling = tcp_layer.get_field_value('tcp.option_wscale_val') or '0'
                
                # Opciones TCP (NOP, SACK, etc.)
                opciones_lista = []
                options = tcp_layer.options
                if 'nop' in options:
                    opciones_lista.append('nop')
                if 'mss' in options:
                    opciones_lista.append('mss')
                if 'ws' in options:
                    opciones_lista.append('ws')
                if 'sok' in options:  # SACK permitted
                    opciones_lista.append('sok')

                # Don't Fragment Flag
                dont_fragment = 'df' if ip_layer.flags_df == '1' else ''
                
                # Construir la firma TCP
                opciones = ','.join(opciones_lista) if opciones_lista else 'nop'
                firma = f"{ip_version}:{ttl}+0:0:{mss}:{window_size},2:{opciones}:{dont_fragment},id+:0"
                if firma:
                    firmas_tcp.append(firma)
                if len(firmas_tcp)>=5:
                    break
            os.remove("tcp_syn.pcap")
        except AttributeError as e:
            logger.warning(f"Error procesando el paquete: {e}")

    logger.info (firmas_tcp)
    return firmas_tcp
#TODO: Metodo completo
def get_tcp_syn_ack_signatures(ip):
    return None

def get_arkime_timestamp(ip):
    logger.info(f"SEARCHING TIMESTAMP FOR {ip}")
    malcolm_ip = config['GENERAL']['MALCOLM_IP']

    # Variables para la paginación
    start = 0
    length = 1  # Solo queremos la primera sesión para obtener el timestamp

    # Realizar una solicitud GET a la API de Arkime para obtener las sesiones con la IP dada
    expression = f'ip.src == {ip} || ip.dst == {ip}'
    try:
        response = requests.get(
            f"https://{malcolm_ip}/arkime/api/sessions?expression={expression}&start={start}&length={length}",
            headers=headers,
            auth=auth,
            verify=False,
            timeout=10  # Establecer un tiempo máximo de espera de 10 segundos por solicitud
        )
    except requests.exceptions.RequestException as e:
        logger.error(f"Request failed: {e}")
        return None

    # Verificar el estado de la respuesta
    if response.status_code != 200:
        logger.error(f"Error fetching sessions: {response.status_code} - {response.text}")
        return None

    # Intentar procesar la respuesta como JSON
    try:
        response_data = response.json()
    except ValueError as e:
        logger.error(f"Failed to parse JSON response: {e}")
        return None

    # Revisar si la respuesta contiene datos
    sessions = response_data.get('data', [])
    logger.debug(f"Sessions found: {len(sessions)}")

    # Si se encontraron sesiones, extraer el timestamp de la primera
    if sessions:
        logger.debug(f"Session data: {sessions[0]}")
        timestamp = sessions[0].get('firstPacket')
        if timestamp:
            logger.info(f"Timestamp found: {timestamp}")
            return timestamp
        else:
            logger.info("No timestamp found in the session data.")
            return None
    else:
        logger.info("No sessions found for the given IP.")
        return None
    
###############################################################################################
# Funciones auxiliares
###############################################################################################
def get_real_pcaps(expression, gen_pcap=False):
    try:
        params = {
            "expression": expression,
            "date": config['ARKIME']['BACKTIME_SEARCH'],
            "length": config['ARKIME']['PCAP_SESSIONS_SIZE'],
        }
        response = requests.post(
            f"https://{config['GENERAL']['MALCOLM_IP']}/arkime/api/sessions",
            headers=headers,
            json=params,
            auth=auth,
            verify=False
        )
        if response.status_code == 200:
            # Intenta parsear la respuesta como JSON
            sessions = response.json().get("data", [])
            logger.info(f"Total Sessions Found in Arkime: {len(sessions)}")

            # Extraer los IDs de sesión
            session_ids = [session['id'] for session in sessions]
            ids_param = ','.join(session_ids)
            logger.debug(f"Sessions ids: {ids_param}")
            if ids_param != "":
                pcap_url = f"https://{config['GENERAL']['MALCOLM_IP']}/arkime/api/sessions/pcap/test.pcap"
                response = requests.get(
                    pcap_url,
                    params={"ids": ids_param, "date": -1},  # Puedes ajustar otros parámetros según sea necesario
                    auth=HTTPBasicAuth(config['NGINX']['USER'], config['NGINX']['PASSWORD']),
                    verify=False
                )
                if response.status_code == 200:
                    if gen_pcap:
                        with open(gen_pcap, "wb") as f:
                            f.write(response.content)
                        return gen_pcap
                    else:
                        return rdpcap(BytesIO(response.content))
                else:
                    logger.info(f"Error downloading PCAP: {response.status_code} - {response.text}")
    except requests.exceptions.RequestException as e:
        logger.info(f"Failed: {e}")
    except scapy.Scapy_Exception as e:
        logger.warning ("Downloaded file not readable or empty")
    return None

def obtener_todos_los_dispositivos():
    # Función para obtener todos los datos de todos los dispositivos
    dispositivos_url = f"https://{config['GENERAL']['MALCOLM_IP']}/netbox/api/dcim/devices/"
    siguiente_pagina = dispositivos_url
    dispositivos = []

    while siguiente_pagina:
        response = session.get(siguiente_pagina, headers=headers, auth=auth, verify=False)

        if response.status_code == 200:
            data = response.json()
            dispositivos.extend(data.get('results', []))
            siguiente_pagina = data.get('next')  # Obtener la siguiente página si existe
        else:
            print(f"Error al obtener los dispositivos: {response.status_code} - {response.text}")
            break

    return dispositivos

def eliminar_etiquetas(dispositivo):
    # Función para eliminar las etiquetas "enriquecido" y "fingerbank" de un dispositivo
    dispositivo_id = dispositivo.get('id')
    dispositivo_url = f"https://{config['GENERAL']['MALCOLM_IP']}/netbox/api/dcim/devices/{dispositivo_id}/"
    csrf_token = obtener_csrf_token()
    headers = {
        "Authorization": f"Token {config['NETBOX']['TOKEN']}",
        "X-CSRFToken": csrf_token,
        "Content-Type": "application/json",
        "Referer": f"https://{config['GENERAL']['MALCOLM_IP']}/netbox/",
    }
    # Obtener los datos actuales del dispositivo
    response = session.get(dispositivo_url, headers=headers, auth=auth, verify=False)
    
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
        response = session.patch(dispositivo_url, headers=headers, json=update_data, auth=auth, verify=False)

        if response.status_code == 200:
            print(f"Se eliminaron las etiquetas de 'enriquecido' y 'fingerbank' para el dispositivo {dispositivo.get('name')}.")
        else:
            print(f"Error al actualizar las etiquetas del dispositivo {dispositivo.get('name')}: {response.status_code} - {response.text}")
    else:
        print(f"El dispositivo {dispositivo.get('name')} no tiene etiquetas 'enriquecido' o 'fingerbank'.")

def obtener_csrf_token():
    # Función para obtener el token CSRF
    login_url = f"https://{config['GENERAL']['MALCOLM_IP']}/netbox/login/"
    session.get(login_url, auth=HTTPBasicAuth(config['NGINX']['USER'], config['NGINX']['PASSWORD']), verify=False)
    csrf_token = session.cookies.get('csrftoken')
    return csrf_token

def is_enriched(device_id, tag = "enriquecido"):
    # Función para comprobar si el dispositivo tiene la etiqueta "Enriquecido"
    dispositivo_url = f"https://{config['GENERAL']['MALCOLM_IP']}/netbox/api/dcim/devices/{device_id}/"
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
    interfaces_url = f"https://{config['GENERAL']['MALCOLM_IP']}/netbox/api/dcim/interfaces/?device_id={device_id}"
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
        logger.warning(f"Error al obtener las etiquetas para el dispositivo {device_id}: {response.status_code}")

    return None
# Función para obtener la dirección MAC de una máquina virtual
def obtener_mac_maquina_virtual(vm_id):
    interfaces_url = f"https://{config['GENERAL']['MALCOLM_IP']}/netbox/api/virtualization/interfaces/?virtual_machine_id={vm_id}"
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
        logger.warning(f"Error al obtener las interfaces para la máquina virtual {vm_id}: {response.status_code} - {response.text}")

    return None

def obtener_activos_ips_y_macs(num=-1):
    lista_activos = []
    activos_urls = [
        f"https://{config['GENERAL']['MALCOLM_IP']}/netbox/api/dcim/devices/",  # URL para obtener dispositivos
        f"https://{config['GENERAL']['MALCOLM_IP']}/netbox/api/virtualization/virtual-machines/"  # URL para obtener máquinas virtuales
    ]
    control = False
    if num > 0:
        control = True

    # Iterar sobre ambas URLs para obtener dispositivos y máquinas virtuales
    for activos_url in activos_urls:
        siguiente_pagina = activos_url
        while siguiente_pagina:
            response = session.get(siguiente_pagina, headers=headers, auth=HTTPBasicAuth(config['NGINX']['USER'], config['NGINX']['PASSWORD']), verify=False)

            if response.status_code == 200:
                data = response.json()
                activos = data.get('results', [])

                # Procesar los activos en la página actual
                for activo in activos:
                    nombre = activo.get('name', 'Desconocido')
                    direccion_ip = activo.get('primary_ip', {}).get('address', 'No especificada')
                    activo_id = activo.get('id')
                    tipo_activo = 'dispositivo' if 'device_type' in activo else 'maquina_virtual'
                    direccion_mac = None

                    if tipo_activo == 'dispositivo':
                        direccion_mac = obtener_mac_dispositivo(activo_id)
                    elif tipo_activo == 'maquina_virtual':
                        # Obtener la dirección MAC de la interfaz principal de la máquina virtual
                        direccion_mac = obtener_mac_maquina_virtual(activo_id)

                    # Separar la dirección IP y la máscara si es posible
                    ip, mascara = direccion_ip.split('/') if '/' in direccion_ip else (direccion_ip, None)
                    enriched = is_enriched(activo_id)
                    fingerbanked = is_enriched(activo_id, "fingerbank")

                    # Añadir el activo a la lista solo si no está enriquecido o fingerbanked
                    if not enriched or not fingerbanked:
                        lista_activos.append({
                            'id': activo_id,
                            'name': nombre,
                            'ip': ip,
                            'mac': direccion_mac,
                            'enriched': enriched,
                            'fingerbanked': fingerbanked,
                            'tipo': tipo_activo
                        })
                    logger.info(f"Activo: {nombre}, IP: {ip}, MAC: {direccion_mac}, Tipo: {tipo_activo}")

            else:
                logger.warning(f"Error al obtener los activos desde {activos_url}: {response.status_code} - {response.text}")
                break

            # Obtener la siguiente página, si existe
            siguiente_pagina = data.get('next')
            if siguiente_pagina:
                logger.info(f"Obteniendo la siguiente página de activos: {siguiente_pagina}")

            # Verificar si se alcanzó el límite especificado
            if len(lista_activos) >= num and control:
                break

    return lista_activos
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

    #Llamada a la funcion de timestamp
    timestamp = get_arkime_timestamp(ip)
    logger.debug(f"Timestamp obtenido de Arkime para IP {ip}: {timestamp}")  # Registro de depuración
    result["timestamp"] = timestamp if timestamp else None

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
    dispositivo_url = f"https://{config['GENERAL']['MALCOLM_IP']}/netbox/api/dcim/devices/{dispositivo_id}/"
    csrf_token = obtener_csrf_token()
    headers = {
        "Authorization": f"Token {config['NETBOX']['TOKEN']}",
        "X-CSRFToken": csrf_token,
        "Content-Type": "application/json",
        "Referer": f"https://{config['GENERAL']['MALCOLM_IP']}/netbox/",
    }
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
        etiquetas_url = f"https://{config['GENERAL']['MALCOLM_IP']}/netbox/api/extras/tags/?slug=fingerbank"
        response = session.get(etiquetas_url, headers=headers, auth=HTTPBasicAuth(config['NGINX']['USER'], config['NGINX']['PASSWORD']), verify=False)
        
        if response.status_code == 200:
            data = response.json()
            fingerbank_tag = data.get("results", [])[0]
            fingerbank_id = fingerbank_tag["id"]
            etiquetas_actuales.append({"id": fingerbank_id})
        else:
            print(f"Error al obtener la etiqueta 'Fingerbank': {response.status_code} - {response.text}")

    if not enriched:
        etiquetas_url = f"https://{config['GENERAL']['MALCOLM_IP']}/netbox/api/extras/tags/?slug=enriquecido"
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
# Función para obtener los datos de configuración de contexto de un dispositivo
def obtener_datos_contexto_dispositivo(device_id):
    dispositivo_url = f"https://{config['GENERAL']['MALCOLM_IP']}/netbox/api/dcim/devices/{device_id}/"
    response = session.get(dispositivo_url, headers=headers, auth=HTTPBasicAuth(config['NGINX']['USER'], config['NGINX']['PASSWORD']), verify=False)

    if response.status_code == 200:
        dispositivo = response.json()
        return dispositivo.get('config_context', {})
    else:
        print(f"Error al obtener los datos de contexto para el dispositivo {device_id}: {response.status_code} - {response.text}")
        return {}
# Función para obtener la lista de dispositivos y generar los JSON de contexto
def generar_json():
    dispositivos_url = f"https://{config['GENERAL']['MALCOLM_IP']}/netbox/api/dcim/devices/"
    siguiente_pagina = dispositivos_url

    while siguiente_pagina:
        response = session.get(siguiente_pagina, headers=headers, auth=HTTPBasicAuth(config['NGINX']['USER'], config['NGINX']['PASSWORD']), verify=False)
        if response.status_code == 200:
            data = response.json()
            dispositivos = data.get('results', [])

            # Procesar los dispositivos en la página actual
            for dispositivo in dispositivos:
                nombre = dispositivo.get('name', 'Desconocido').strip()  # Eliminamos espacios en blanco y caracteres innecesarios
                dispositivo_id = dispositivo.get('id')

                # Obtener los datos de contexto de configuración y generar un archivo JSON
                datos_contexto = obtener_datos_contexto_dispositivo(dispositivo_id)
                
                if datos_contexto:
                    # Definir nombre del archivo sin comillas ni caracteres adicionales
                    nombre_archivo = f"{nombre}_config_context.json"
                    # Asegurarse de que no haya comillas
                    nombre_archivo = nombre_archivo.replace('"', '').replace("'", '')

                    # Guardar los datos de contexto en un archivo .json
                    with open(nombre_archivo, 'w') as json_file:
                        json.dump(datos_contexto, json_file, indent=4)
                    print(f"Generado archivo {nombre_archivo} con los datos de contexto de configuración.")
                else:
                    print(f"El dispositivo {nombre} no tiene datos de contexto de configuración.")

            # Obtener la siguiente página
            siguiente_pagina = data.get('next')
        else:
            print(f"Error al obtener los dispositivos: {response.status_code} - {response.text}")
            break
# Función que escribe los assets actualizados en elastic
def send_to_elastic(asset):
    if (config['ELASTIC']['URL'] != None):
        client = Elasticsearch(
            config['ELASTIC']['URL'],
            api_key=config['ELASTIC']['TOKEN'],
            verify_certs=False
        )

        documents = [
            { "index": { "_index": config['ELASTIC']['INDEX_NAME'], "_id": asset["id"]}},
            asset,
        ]

        client.bulk(operations=documents, pipeline="ent-search-generic-ingestion")
