import json
from random import Random
import datetime


def get_categorie_of(domain_name):
    for key, value in groups_data.items():
        if domain_name in value:
            return key
    return None

def get_random_domain_from(categorie):
    return b.choices(groups_data[categorie])

def save_timeline_file(user_mac_address, final_timeline):
    filename = user_mac_address + '-Timeline.json'
    with open(filename, "w") as outfile:
        outfile.write(json.dumps(final_timeline, indent=4, default=str))


if __name__ == '__main__':
    user_mac_address = '6c:96:cf:e0:ef:a7'
    information_file_name = user_mac_address + '-statistics.json'

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
    a = Random()
    b = Random()
    for zone_information in zone_statistics["Zone information"].values():
        zone_header = {
                    "HandlerType": "BrowserFirefox",
                    "Initial": "about:blank",
                    "UtcTimeOn": str(datetime.datetime.fromtimestamp(zone_information["Start time"])).split(" ")[1],
                    "UtcTimeOff": str(datetime.datetime.fromtimestamp(zone_information["End time"])).split(" ")[1],
                    "Loop": "True",
                    "TimeLineEvents": []
        }
        for time_key, value in timeline.items():
            for activity in value:
                if int(time_key) >= int(zone_information["Start time"]) and int(time_key) <= int(zone_information["End time"]):
                    event_struct = {
                            "Command": "browse",
                            "CommandArgs": [get_random_domain_from(get_categorie_of(initial_domain))],
                            "DelayAfter": activity["Total duration"],
                            "DelayBefore": 0
                    }
                    zone_header["TimeLineEvents"].append(event_struct)
                    random = a.randint(0, 100)
                    cumulative_proba = 0
                    for key, value in markov_chain[initial_domain].items():
                        cumulative_proba += value
                        if (random <= cumulative_proba):
                            initial_domain = key
                            break
        timeline_file["TimeLineHandlers"].append(zone_header)
    save_timeline_file(user_mac_address, timeline_file)
