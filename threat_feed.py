import requests
import pandas as pd

def get_threat_feed():

    url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"

    try:
        response = requests.get(url, timeout=10)

        data = response.json()

        records = []

        for item in data[:20]:
            records.append({
                "IP Address": item.get("ip_address"),
                "Malware": item.get("malware"),
                "Status": item.get("status")
            })

        return pd.DataFrame(records)

    except:
        return pd.DataFrame()