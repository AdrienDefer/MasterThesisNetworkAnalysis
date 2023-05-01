import pyshark


# LAYER FILTER

# Return True if the packet has an IP
def has_network_layer(packet):
    if "IP" in packet or "IPv6" in packet:
        return True
    return False
    
# Return True if the packet has TCP
def has_transport_layer(packet):
    if "TCP" in packet:
        return True
    return False
    
# Return True if the packet has TLS
def has_presentation_layer(packet):
    if "TLS" in packet:
        return True
    return False
    
# Return True if the packet has port 443 (HTTPS)
def has_application_layer(packet):
    if "443" in get_transport_layer_info(packet):
        return True
    return False

# LAYER INFORMATION

# Return [IPversion, Src IP, Dst IP]
def get_network_layer_info(packet):
    if "IP" in packet:
        return [4, packet.ip.src, packet.ip.dst]
    if "IPv6" in packet:
        return [6, packet.ipv6.src, packet.ipv6.dst]
    
# Return [Src Port, Dst Port]
def get_transport_layer_info(packet):
    return [packet.tcp.srcport, packet.tcp.dstport]

def is_available_domain_name(domain_name):
    # This list can be updated
    if domain_name.split(".")[0] == "www":
        return True
    return False

def get_mac_address(packet, direction):
    if (direction == "IN"):
        return str(packet.eth.dst_resolved)
    else:
        return str(packet.eth.src_resolved)