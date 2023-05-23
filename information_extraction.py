from classes import *
from functions import *


START_TIME = 1682056800
END_TIME = 1682110800

if __name__ == '__main__':
    print("Start Network Analysis Software...")
    analysis = NetworkAnalysis(START_TIME, END_TIME, ["6c:96:cf:e0:ef:a7"])

    for i in range(1, 17):
        packet_file = '/Users/adrien/Downloads/NetworkTraceFiles/OneDayTraffic_' + str(i) + '.pcap'
        packets = pyshark.FileCapture(packet_file)
        print("Start process for " + packet_file + " ...")
        for packet in packets:
            is_useful_packet = analysis.is_useful_packet(packet)
            if is_useful_packet in ["OUT", "IN"]:
                direction = is_useful_packet
                if analysis.is_https_packet(packet):
                    analysis.update_global_statistics(packet, direction)
                    if has_presentation_layer(packet):
                        try:
                            # If the handshake type is 1
                            if "Client Hello" in packet.tls.record:
                                if is_available_domain_name(str(packet.tls.handshake_extensions_server_name)):
                                    analysis.update_domain_names_statistics(packet)
                                    analysis.update_users_domain_names_statistics(packet, direction)
                                    analysis.manage_users_activities("init", packet, direction)
                            else:
                                analysis.manage_users_activities("update", packet, direction)
                        except AttributeError:
                            continue
                    else:
                        analysis.manage_users_activities("update", packet, direction)
        print("End process for " + packet_file + " ...")
        packets.close()
    analysis.update_users_zones_statistics()
    analysis.clean_activities_dictionary()
    analysis.save_global_statistics()
    print("Stop Network Analysis Software...")
    