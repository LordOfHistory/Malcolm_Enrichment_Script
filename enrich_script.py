from enrichment_lib import *
from elasticsearch import Elasticsearch

if __name__ == "__main__":
    # Inicializar el cliente de Elasticsearch
    es_client = Elasticsearch(
        config['ELASTIC']['URL'],
        api_key=config['ELASTIC']['TOKEN'],
        verify_certs=False
    )
    
    # Crear el índice en Elasticsearch si no existe (solo una vez)
    #create_index_with_mapping(es_client, config['ELASTIC']['INDEX_NAME'])  # Descomentar si necesitas crear el índice con el mapeo ECS

    # Ejecutar la función para obtener las IPs y MACs de todos los dispositivos
    list_assets = obtener_activos_ips_y_macs(int(config['ENRICHMENT']['BATCH_SIZE']))

    for asset in list_assets:
        # Realizar el análisis y enriquecer el asset
        asset["enrichment_data"] = run_analysis(asset["ip"], asset["mac"])
        asset["enriched"] = True

        # Consultar Fingerbank y actualizar el asset con los datos obtenidos
        asset["fingerbank_data"] = consultar_fingerbank(
            asset["mac"], 
            asset["enrichment_data"]["dhcp_fingerprint"],
            asset["enrichment_data"]["dhcp_vendor"], 
            asset["enrichment_data"]["dhcpv6_fingerprint"], 
            asset["enrichment_data"]["user_agents"], 
            asset["enrichment_data"]["mdns_services"], 
            asset["enrichment_data"]["tcp_syn_signatures"], 
            asset["enrichment_data"]["tcp_syn_ack_signatures"], 
            asset["enrichment_data"]["ja3_fingerprints"], 
            asset["enrichment_data"]["ja3_data"], 
            asset["enrichment_data"]["hostname"], 
            asset["enrichment_data"]["destination_hosts"]
        )
        
        asset["fingerbanked"] = asset["fingerbank_data"] is not None
        
    for asset in list_assets:
        # Actualizar los datos y etiquetas en NetBox (si es necesario)
        write_data(asset["id"], asset)

        # Convertir el asset al formato ECS para Elasticsearch
        ecs_asset = adaptar_a_ecs(asset)  # Adaptación a ECS en enrichment_lib.py

        # Enviar el asset a Elasticsearch en formato ECS
        send_to_elastic(ecs_asset)  # Enviar el ECS asset

        # Registrar el asset en el log
        logger.info(ecs_asset)
