from enrichment_lib import *

if __name__ == "__main__":
    # Ejecutar la función para obtener las IPs y MACs de todos los dispositivos
    list_assets = obtener_activos_ips_y_macs(int(config['ENRICHMENT']['BATCH_SIZE']))

    for asset in list_assets:
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
        adaptar_a_ecs(asset)
        send_to_elastic(asset)
        logger.info (asset)
