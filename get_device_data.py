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

config = configparser.ConfigParser()
config.read('config.ini')
logger = logging.getLogger(__name__)
logging.basicConfig(level=(int(config['GENERAL']['LOG_LEVEL'])*10))
warnings.simplefilter('ignore', InsecureRequestWarning)
headers = {"Content-Type": "application/json"}
auth=HTTPBasicAuth(config['NGINX']['USER'], config['NGINX']['PASSWORD'])

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

""" def get_hostname(ip):
    logger.debug("SEARCHING HOSTNAME FOR "+ ip)
    # URL de la API de NetBox
    NETBOX_URL = f"https://{config['GENERAL']['MALCOLM_IP']}/netbox/api"
    API_TOKEN = config['NETBOX']['TOKEN']
    NGINX_USER = config['NGINX']['USER']
    NGINX_PASSWORD = config['NGINX']['PASSWORD']

    # Crear una sesión para manejar cookies
    session = requests.Session()

    # Hacer una solicitud GET para obtener el token CSRF
    login_url = f"https://{config['GENERAL']['MALCOLM_IP']}/netbox/login/"
    session.get(login_url, auth=HTTPBasicAuth(NGINX_USER, NGINX_PASSWORD), verify=False)

    # Obtener la cookie CSRF del navegador
    csrf_token = session.cookies.get('csrftoken')

    # Añadir encabezados de autorización y CSRF
    headers = {
        "Authorization": f"Token {API_TOKEN}",
        "X-CSRFToken": csrf_token,
        "Content-Type": "application/json",
        "Referer": f"https://{config['GENERAL']['MALCOLM_IP']}/netbox/",
    }
    # URL para buscar la dirección IP en NetBox
    search_url = f"{NETBOX_URL}/ipam/ip-addresses/?q={ip}"
    
    # Resolvemos primero el dominio, a ver si hay algo públicamente
    hostname = False
    if not ipaddress.ip_address(ip).is_private:
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                if hostname:
                    logger.debug("Found public hostname: "+hostname)
            except socket.herror:
                logger.debug("Domain for this IP not found publicly")
    # Realizar la solicitud GET para obtener los detalles de la IP
    response = session.get(search_url, headers=headers, auth=HTTPBasicAuth(NGINX_USER, NGINX_PASSWORD), verify=False)
    if not hostname:
        if response.status_code == 200:
            # Procesar la respuesta JSON para extraer el hostname
            data = response.json()
            if data['count'] > 0:
                # Si se encuentra la IP, obtener el nombre del dispositivo asociado
                ip_data = data['results'][0]
                hostname = ip_data.get('assigned_object', {}).get('device', {}).get('name', ip)
                if hostname != ip:
                    logger.debug("Found local hostname: "+hostname)
                else:
                    logger.debug("No results found for the given IP locally")
                    hostname = ip
            else:
                logger.debug("No results found for the given IP locally")
        else:
            logger.debug(f"Error fetching IP details: {response.status_code} - {response.text}")
    return hostname
 """
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

def get_tcp_syn_ack_signatures(ip):
    return None

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

#def test():
    #get_client_hints('10.14.2.66')
    #get_dhcp_fingerprint('00:0c:29:56:59:7d')
    #get_dhcpv6_fingerprint('08:00:27:fe:8f:95')
    #get_dhcpv6_enterprise('08:00:27:fe:8f:95')
    #get_dhcp_vendor('00:0c:29:56:59:7d')
    #get_destination_hosts('10.14.2.229')
    #get_hostname('8.8.8.8')
#get_ja3_fingerprints('10.14.1.100')
#get_ja3_fingerprints('10.14.1.100')
    #get_ja3_data('10.14.2.229')
    #get_mdns_services('192.168.42.70')
    #get_tcp_syn_signatures('10.14.2.229')
    #get tcp_syn_ack_signatures('10.14.2.229')
    #get_user_agent('10.14.2.229')