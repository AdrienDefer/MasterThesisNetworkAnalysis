import json
import random
import datetime


ghosts_timeline = {"HandlerType": "BrowserFirefox",
                   "Initial": "about:blank",
                   "UtcTimeOn": "12:00:00",
                   "UtcTimeOff": "12:30:00",
                   "Loop": "True",
                   "TimeLineEvents": [{}, {}]}

def get_categorie_of(domain_name):
    for key, value in groups_data.items():
        if domain_name in value:
            return key
    return None

def get_random_domain_from(categorie):
    return random.choices(groups_data[categorie])

def save_timeline_file(user_mac_address, final_timeline):
    filename = user_mac_address + '-Timeline.json'
    with open(filename, "w") as outfile:
        outfile.write(json.dumps(final_timeline, indent=4, default=str))


if __name__ == '__main__':
    user_mac_address = '6c:96:cf:e0:ef:a7'
    information_file_name = user_mac_address + '-Statistics.json'

    information_file = open(information_file_name, 'r')
    user_data = json.load(information_file)
    information_file.close()

    groups_file = open('groups.json', 'r')
    groups_data = json.load(groups_file)
    groups_file.close()

    zone_statistics = user_data["Zones statistics"]
    markov_chain = user_data["Markov chain"]
    timeline = user_data["Timeline"]

    timeline_file = {"TimeLineHandlers": []}
    initial_domain = timeline[list(timeline.keys())[0]][0]["Domain name"]
    for zone_information in zone_statistics["Zone information"].values():
        zone_header = {
                        "HandlerType": "BrowserFirefox",
                        "Initial": "about:blank",
                        "UtcTimeOn": str(datetime.datetime.fromtimestamp(zone_information["Start time"])).split(" ")[1],
                        "UtcTimeOff": str(datetime.datetime.fromtimestamp(zone_information["End time"])).split(" ")[1],
                        "Loop": "True",
                        "TimeLineEvents": []
        }
        for item in timeline.values():
            for event in item:
                if int(event["Start time"]) > zone_information["Start time"] and int(event["Start time"]) < zone_information["End time"]:
                    event_struct = {
                        "Command": "browse",
                        "CommandArgs": [get_random_domain_from(get_categorie_of(initial_domain))],
                        "DelayAfter": (zone_information["End time"] - zone_information["Start time"]) / zone_information["Domain contacted in the zone"],
                        "DelayBefore": 0
                    }
                    zone_header["TimeLineEvents"].append(event_struct)
                    if (initial_domain in markov_chain.keys()):
                        initial_domain = random.choice(list(markov_chain[initial_domain].keys()))
                    else:
                        initial_domain = random.choice(list(markov_chain.keys()))
                else:
                    break
        timeline_file["TimeLineHandlers"].append(zone_header)
    save_timeline_file(user_mac_address, timeline_file)