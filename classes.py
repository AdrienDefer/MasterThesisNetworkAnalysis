from functions import *
import json
from datetime import datetime





# Global internet statistics
class NetworkAnalysis:
    def __init__(self, trace_start_time, trace_end_time, internet_users_mac_address):
        self.internet_users_dictionary = {}
        self.global_rate_statistics = {}
        self.global_characteristics = {"Packet_sent": 0, "Packet_received": 0, "Total_packet": 0, "Bit_sent": 0, "Bit_received": 0, "Total_bit": 0}
        self.domain_names_statistics = {"Domain contacted": [], "Number contacted": 0, "Unduplicated contacted": 0, "Rate": {}}
        self.trace_start_time = trace_start_time
        self.trace_end_time = trace_end_time
        self.init_stats_dictionaries()
        for address in internet_users_mac_address:
            self.internet_users_dictionary[address] = InternetUser(address, trace_start_time, trace_end_time)
        self.current_timestamp = 0.0
        
    def init_stats_dictionaries(self):
        for i in range(self.trace_start_time, self.trace_end_time):
            self.global_rate_statistics[i] = {"Bits_rate": {"Ingoing": 0, "Outgoing": 0, "Total": 0}, "Packets_rate": {"Ingoing": 0, "Outgoing": 0, "Total": 0}, "Inter_time_rate": {"Ingoing": 0.0, "Outgoing": 0.0, "Total": 0.0}, "Protocols_rate": {"Ingoing": {}, "Outgoing": {}, "Total": {}}}
            self.domain_names_statistics["Rate"][i] = 0

    def get_internet_users(self):
        for value in self.internet_users_dictionary.values():
            value.show()
    
    def get_specific_user(self, MAC_address):
        return self.internet_users_dictionary[MAC_address]
    
    def is_useful_packet(self, packet):
        if (str(packet.eth.src_resolved) in self.internet_users_dictionary.keys()):
            return "OUT"
        elif (str(packet.eth.dst_resolved) in self.internet_users_dictionary.keys()):
            return "IN"
        else:
            return "NO"
        
    # Only accepts packet from HTTPS protocol (port 443) --> Can be adapted to another protocol
    def is_https_packet(self, packet):
        if has_network_layer(packet):
            if has_transport_layer(packet):
                if has_application_layer(packet):
                     return True
        return False
            
    def update_global_statistics(self, packet, direction):
        key = int(packet.sniff_timestamp.split(".")[0])
        if self.current_timestamp == 0.0:
            self.current_timestamp = float(packet.sniff_timestamp)
        packet_timestamp = float(packet.sniff_timestamp)
        protocol = packet.highest_layer
        if direction == "IN":
            self.global_rate_statistics[key]["Bits_rate"]["Ingoing"] += (int(packet.length) * 8)
            self.global_rate_statistics[key]["Packets_rate"]["Ingoing"] += 1
            if self.global_rate_statistics[key]["Inter_time_rate"]["Ingoing"] == 0.0:
                self.global_rate_statistics[key]["Inter_time_rate"]["Ingoing"] = packet_timestamp - self.current_timestamp
            else:
                self.global_rate_statistics[key]["Inter_time_rate"]["Ingoing"] = (self.global_rate_statistics[key]["Inter_time_rate"]["Ingoing"] + (packet_timestamp - self.current_timestamp)) / 2
            self.global_characteristics["Packet_received"] += 1
            self.global_characteristics["Bit_received"] += (int(packet.length) * 8)
            
            if protocol not in self.global_rate_statistics[key]["Protocols_rate"]["Ingoing"].keys():
                self.global_rate_statistics[key]["Protocols_rate"]["Ingoing"][protocol] = 1
            else:
                self.global_rate_statistics[key]["Protocols_rate"]["Ingoing"][protocol] += 1
        else:
            self.global_rate_statistics[key]["Bits_rate"]["Outgoing"] += (int(packet.length) * 8)
            self.global_rate_statistics[key]["Packets_rate"]["Outgoing"] += 1
            if self.global_rate_statistics[key]["Inter_time_rate"]["Outgoing"] == 0.0:
                self.global_rate_statistics[key]["Inter_time_rate"]["Outgoing"] = packet_timestamp - self.current_timestamp
            else:
                self.global_rate_statistics[key]["Inter_time_rate"]["Outgoing"] = (self.global_rate_statistics[key]["Inter_time_rate"]["Outgoing"] + (packet_timestamp - self.current_timestamp)) / 2
            self.global_characteristics["Packet_sent"] += 1
            self.global_characteristics["Bit_sent"] += (int(packet.length) * 8)
            if protocol not in self.global_rate_statistics[key]["Protocols_rate"]["Outgoing"].keys():
                self.global_rate_statistics[key]["Protocols_rate"]["Outgoing"][protocol] = 1
            else:
                self.global_rate_statistics[key]["Protocols_rate"]["Outgoing"][protocol] += 1

        if self.global_rate_statistics[key]["Inter_time_rate"]["Total"] == 0.0:
            self.global_rate_statistics[key]["Inter_time_rate"]["Total"] = packet_timestamp - self.current_timestamp
        else:
            self.global_rate_statistics[key]["Inter_time_rate"]["Total"] = (self.global_rate_statistics[key]["Inter_time_rate"]["Total"] + (packet_timestamp - self.current_timestamp)) / 2
            
        self.current_timestamp = packet_timestamp

        self.global_rate_statistics[key]["Bits_rate"]["Total"] += (int(packet.length) * 8)
        self.global_rate_statistics[key]["Packets_rate"]["Total"] += 1
        self.global_characteristics["Total_packet"] += 1
        self.global_characteristics["Total_bit"] += (int(packet.length) * 8)

        if protocol not in self.global_rate_statistics[key]["Protocols_rate"]["Total"].keys():
            self.global_rate_statistics[key]["Protocols_rate"]["Total"][protocol] = 1
        else:
            self.global_rate_statistics[key]["Protocols_rate"]["Total"][protocol] += 1

        self.update_users_statistics(packet, direction)

    def update_domain_names_statistics(self, packet):
        self.domain_names_statistics["Number contacted"] += 1
        if str(packet.tls.handshake_extensions_server_name) not in self.domain_names_statistics["Domain contacted"]:
            self.domain_names_statistics["Unduplicated contacted"] += 1
            self.domain_names_statistics["Domain contacted"].append(str(packet.tls.handshake_extensions_server_name))
        key_component = int(packet.sniff_timestamp.split(".")[0])
        key = key_component - (key_component % 60)
        self.domain_names_statistics["Rate"][key] += 1

    def update_users_statistics(self, packet, direction):
        mac_address = get_mac_address(packet, direction)
        for value in self.internet_users_dictionary.values():
            if value.get_mac_address() == mac_address:
                value.update_statistics(packet, direction)
    
    def update_users_domain_names_statistics(self, packet, direction):
        mac_address = get_mac_address(packet, direction)
        for value in self.internet_users_dictionary.values():
            if value.get_mac_address() == mac_address:
                value.update_domain_names_statistics(packet)
    
    def update_users_zones_statistics(self):
        for value in self.internet_users_dictionary.values():
            value.update_zones_statistics()
    
    def manage_users_activities(self, type, packet, direction):
        mac_address = get_mac_address(packet, direction)
        for value in self.internet_users_dictionary.values():
            if value.get_mac_address() == mac_address:
                value.activities_management(type, packet, direction)

    def clean_activities_dictionary(self):
        for value in self.internet_users_dictionary.values():
            value.clean_activities_dictionary()

    def save_global_statistics(self):
        global_dictionary = {"Bits statistics": {"Ingoing": self.global_characteristics["Bit_received"], 
                                                 "Outgoing": self.global_characteristics["Bit_sent"], 
                                                 "Total": self.global_characteristics["Total_bit"]}, 
                             "Packets statistics":
                                                 {"Ingoing": self.global_characteristics["Packet_received"],
                                                  "Outgoing": self.global_characteristics["Packet_sent"],
                                                  "Total": self.global_characteristics["Total_packet"]},
                             "Domain names statistics": 
                                                 {"Domain contacted": self.domain_names_statistics["Domain contacted"],
                                                  "Number contacted": self.domain_names_statistics["Number contacted"],
                                                  "Unduplicated contacted": self.domain_names_statistics["Unduplicated contacted"]},
                             "Rate statistics": self.global_rate_statistics}
        with open("global-statistics.json", "w") as outfile:
            outfile.write(json.dumps(global_dictionary, indent=4, default=str))
        for value in self.internet_users_dictionary.values():
            value.save_user_statistics()






# Internet user statistics
class InternetUser:
    def __init__(self, MAC_address, trace_start_time, trace_end_time):
        self.bits_statistics = {"Ingoing": 0, "Outgoing": 0, "Total": 0, "Rate": {}}
        self.packets_statistics = {"Ingoing": 0, "Outgoing": 0, "Total": 0, "Rate": {}}
        self.domain_names_statistics = {"Domain contacted": [], "Number contacted": 0, "Unduplicated contacted": 0, "Rate": {}}
        self.zones_statistics = {"Zone number": 0, "Zone information": {}}
        self.activities_dictionary = {"Address in use": {}, "Activities information": {}}
        self.MAC_address = MAC_address
        self.trace_start_time = trace_start_time
        self.trace_end_time = trace_end_time
        self.init_stats_dictionaries()
    
    def init_stats_dictionaries(self):
        for i in range(self.trace_start_time, self.trace_end_time):
            self.bits_statistics["Rate"][i] = 0
            self.packets_statistics["Rate"][i] = 0
        for i in range(self.trace_start_time, self.trace_end_time, 60):
            self.domain_names_statistics["Rate"][i] = 0
    
    def update_statistics(self, packet, direction):
        if direction == "IN":
            self.bits_statistics["Ingoing"] += (int(packet.length) * 8)
            self.packets_statistics["Ingoing"] += 1
        else:
            self.bits_statistics["Outgoing"] += (int(packet.length) * 8)
            self.packets_statistics["Outgoing"] += 1
        self.bits_statistics["Total"] += (int(packet.length) * 8)
        self.packets_statistics["Total"] += 1
        
        key = int(packet.sniff_timestamp.split(".")[0])
        self.bits_statistics["Rate"][key] += (int(packet.length) * 8)
        self.packets_statistics["Rate"][key] += 1
    
    def update_domain_names_statistics(self, packet):
        self.domain_names_statistics["Number contacted"] += 1
        if str(packet.tls.handshake_extensions_server_name) not in self.domain_names_statistics["Domain contacted"]:
            self.domain_names_statistics["Unduplicated contacted"] += 1
            self.domain_names_statistics["Domain contacted"].append(str(packet.tls.handshake_extensions_server_name))
        key_component = int(packet.sniff_timestamp.split(".")[0])
        key = key_component - (key_component % 60)
        self.domain_names_statistics["Rate"][key] += 1
        
    def update_zones_statistics(self):
        def close_zone():
            current_zone["End time"] = last_update + threshold
            self.zones_statistics["Zone number"] += 1
            zone_key = "Zone " + str(self.zones_statistics["Zone number"])
            self.zones_statistics["Zone information"][zone_key] = current_zone

        inside_zone = False
        threshold = 600
        current_zone = {"Start time": 0, "End time": 0, "Domain contacted in the zone": 0}
        for key, value in self.domain_names_statistics["Rate"].items():
            if value != 0:
                if not inside_zone:
                    inside_zone = True
                    current_zone["Start time"] = key
                    current_zone["Domain contacted in the zone"] += value
                    last_update = key
                else:
                    if last_update + threshold < key:
                        close_zone()
                        current_zone = {"Start time": 0, "End time": 0, "Domain contacted in the zone": 0}
                        inside_zone = False
                    else:
                        last_update = key
                        current_zone["Domain contacted in the zone"] += value
            else:
                if inside_zone:
                    if last_update + threshold < key:
                        close_zone()
                        current_zone = {"Start time": 0, "End time": 0, "Domain contacted in the zone": 0}
                        inside_zone = False
        if inside_zone:
            close_zone()

    def activities_management(self, type, packet, direction):
        if direction == "IN":
            server_ip = get_network_layer_info(packet)[1]
            session_port = get_transport_layer_info(packet)[1]
        else:
            server_ip = get_network_layer_info(packet)[2]
            session_port = get_transport_layer_info(packet)[0]
        if type == "init":
            self.activities_management_init(server_ip, session_port, packet)
        else:
            self.activities_management_update(server_ip, session_port, packet, direction)
        
    def activities_management_init(self, server_ip, session_port, packet):
        if server_ip in self.activities_dictionary["Address in use"].keys():
            if (session_port not in self.activities_dictionary["Address in use"][server_ip]):
                self.activities_dictionary["Activities information"][server_ip][session_port] = InternetActivity(packet)
                self.activities_dictionary["Address in use"][server_ip].append(session_port)
            else:
                # Port reusability not managed here
                pass
        else:
            self.activities_dictionary["Activities information"][server_ip] = {session_port: InternetActivity(packet)}
            self.activities_dictionary["Address in use"][server_ip] = [session_port]

    def activities_management_update(self, server_ip, session_port, packet, direction):
        if server_ip in self.activities_dictionary["Address in use"].keys():
            if (session_port in self.activities_dictionary["Address in use"][server_ip]):
                self.activities_dictionary["Activities information"][server_ip][session_port].update_statistics(packet, direction)
                
    def get_mac_address(self):
        return self.MAC_address

    def clean_activities_dictionary(self):
        threshold = 5
        has_reference_activity = False
        cleaned_activities_dictionary = {}
        for key, value in self.activities_dictionary["Activities information"].items():
            if key not in cleaned_activities_dictionary.keys():
                cleaned_activities_dictionary[key] = {}
                for activity in value.values():
                    first_time = True
                    if (first_time):
                        current_activity = activity
                        first_time = False
                    if not has_reference_activity:
                        entry = "Session " + str(len(cleaned_activities_dictionary[key]) + 1)
                        cleaned_activities_dictionary[key][entry] = current_activity
                        has_reference_activity = True
                    else:
                        if activity.start_time - cleaned_activities_dictionary[key][entry].start_time <= threshold:
                            cleaned_activities_dictionary[key][entry].merge_activity_with(activity)
                        else:
                            current_activity = activity
                            has_reference_activity = False
            has_reference_activity = False
        self.activities_dictionary = cleaned_activities_dictionary

    def build_activities_timeline(self):
        activities_timeline = {}
        for value in self.activities_dictionary.values():
            for activity in value.values():
                if not activity.get_total_duration() < 0 or not activity.get_total_duration() > 3600:
                    if activity.start_time not in activities_timeline.keys():
                        activities_timeline[activity.start_time] = [activity]
                    else:
                        activities_timeline[activity.start_time].append(activity)
        timeline_keys = list(activities_timeline.keys())
        timeline_keys.sort()
        timeline = {i: activities_timeline[i] for i in timeline_keys}

        return timeline

    def build_markov_chain(self, timeline):
        markov_chain = {}
        previous_activity = None
        for value in timeline.values():
            for activity in value:
                if previous_activity != None:
                    if previous_activity.domain_name not in markov_chain.keys():
                        markov_chain[previous_activity.domain_name] = {}
                    if activity.domain_name not in markov_chain[previous_activity.domain_name].keys():
                        markov_chain[previous_activity.domain_name][activity.domain_name] = 1
                    else:
                        markov_chain[previous_activity.domain_name][activity.domain_name] += 1
                previous_activity = activity
        for key, value in markov_chain.items():
            sum_of_value = sum(value.values())
            for domain_name in value.keys():
                markov_chain[key][domain_name] = (markov_chain[key][domain_name] / sum_of_value) * 100
        display_markov_chain(markov_chain)
        return markov_chain
        
    def save_user_statistics(self):
        timeline = self.build_activities_timeline()
        markov_chain = self.build_markov_chain(timeline)
        for timestamp, activities in timeline.items():
            for i in range(len(activities)):
                timeline[timestamp][i] = timeline[timestamp][i].get_printable_data()
        for address, sessions in self.activities_dictionary.items():
            for session in sessions:
                self.activities_dictionary[address][session] = self.activities_dictionary[address][session].get_printable_data()
        global_dictionary = {"Bits statistics": {"Ingoing": self.bits_statistics["Ingoing"], 
                                                 "Outgoing": self.bits_statistics["Outgoing"], 
                                                 "Total": self.bits_statistics["Total"]}, 
                             "Packets statistics":
                                                 {"Ingoing": self.packets_statistics["Ingoing"],
                                                  "Outgoing": self.packets_statistics["Outgoing"],
                                                  "Total": self.packets_statistics["Total"]}, 
                             "Domain names statistics": 
                                                 {"Domain contacted": self.domain_names_statistics["Domain contacted"],
                                                  "Number contacted": self.domain_names_statistics["Number contacted"],
                                                  "Unduplicated contacted": self.domain_names_statistics["Unduplicated contacted"]},
                             "Zones statistics":{"Zone number": self.zones_statistics["Zone number"],
                                                 "Zone information": self.zones_statistics["Zone information"]},
                             "Activities statistics": self.activities_dictionary,
                             "Markov chain": markov_chain,
                             "Timeline": timeline}
        with open(self.MAC_address + "-statistics.json", "w") as outfile:
            outfile.write(json.dumps(global_dictionary, indent=4, default=str))
    
    def show(self):
        print("This user has the MAC address : " + self.MAC_address)
        



class InternetActivity():
    def __init__(self, packet):
        self.bits_statistics = {"Ingoing": 0, "Outgoing": 0, "Total": 0}
        self.packets_statistics = {"Ingoing": 0, "Outgoing": 0, "Total": 0}
        self.start_time = int(packet.sniff_timestamp.split(".")[0])
        self.end_time = int(packet.sniff_timestamp.split(".")[0])
        self.domain_name = str(packet.tls.handshake_extensions_server_name)
        self.ip = get_network_layer_info(packet)[2]
        self.port = get_transport_layer_info(packet)[0]
        self.bits_statistics["Outgoing"] += (int(packet.length) * 8)
        self.bits_statistics["Total"] += (int(packet.length) * 8)
        self.packets_statistics["Outgoing"] += 1
        self.packets_statistics["Total"] += 1

    def update_statistics(self, packet, direction):
        self.update_bits_statistics(packet, direction)
        self.update_packets_statistics(direction)
        self.set_end_time(int(packet.sniff_timestamp.split(".")[0]))
    
    def set_end_time(self, new_end_time):
        self.end_time = new_end_time
    
    def update_bits_statistics(self, packet, direction):
        if direction == "IN":
            self.bits_statistics["Ingoing"] += (int(packet.length) * 8)
        else:
            self.bits_statistics["Outgoing"] += (int(packet.length) * 8)
        self.bits_statistics["Total"] += (int(packet.length) * 8)
    
    def update_packets_statistics(self, direction):
        if direction == "IN":
            self.packets_statistics["Ingoing"] += 1
        else:
            self.packets_statistics["Outgoing"] += 1
        self.packets_statistics["Total"] += 1

    def get_total_duration(self):
        return self.end_time - self.start_time
    
    def merge_activity_with(self, activity):
        self.end_time = activity.end_time
        if not isinstance(self.port, list):
            self.port = [self.port]
        self.port.append(activity.port)
        self.bits_statistics["Ingoing"] += activity.bits_statistics["Ingoing"]
        self.bits_statistics["Outgoing"] += activity.bits_statistics["Outgoing"]
        self.bits_statistics["Total"] += activity.bits_statistics["Total"]

        self.packets_statistics["Ingoing"] += activity.packets_statistics["Ingoing"]
        self.packets_statistics["Outgoing"] += activity.packets_statistics["Outgoing"]
        self.packets_statistics["Total"] += activity.packets_statistics["Total"]
    
    def get_printable_data(self):
        return {
            "Start time": str(self.start_time),
            "End time": str(self.end_time),
            "Total duration": str(self.get_total_duration()),
            "Domain name": self.domain_name,
            "IP address": self.ip,
            "Port": self.port,
            "Bits statistics": {
                "Ingoing": self.bits_statistics["Ingoing"],
                "Outgoing": self.bits_statistics["Outgoing"],
                "Total": self.bits_statistics["Total"]
            },
            "Packets statistics": {
                "Ingoing": self.packets_statistics["Ingoing"],
                "Outgoing": self.packets_statistics["Outgoing"],
                "Total": self.packets_statistics["Total"]
            }
        }