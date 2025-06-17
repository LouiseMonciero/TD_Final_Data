import requests
import os
import json
import time

def scrap_RSS_items(prefix, start_year, start_index, end_year=2025, folder="data", sleep_between=0.2):
    """ Scrappe les JSON de 'https://www.cert.ssi.gouv.fr/' pour un type (alerte ou avis par exemple) 
    et à partir d'un code donné (CERTFR-2022-0232 par exemple) jusqu'au plus récent. 
    """
    os.makedirs(folder, exist_ok=True)
    for year in range(start_year, end_year + 1):
        i = start_index
        misses = 0
        while misses < 5:  # stop après 5 échecs consécutifs (saut d'alerte de 1 toléré)
            code = f"CERTFR-{year}-{'AVI' if(prefix == 'avis') else 'ALE'}-{str(i).zfill(4)}"
            url = f"https://www.cert.ssi.gouv.fr/{prefix}/{code}/json/"
            print(f"Trying: {url}")
            response = requests.get(url)
            if response.status_code == 200:
                try:
                    myjson = response.json()
                    with open(f"{folder}/{code}.json", "w", encoding="utf-8") as f:
                        json.dump(myjson, f, indent=4, ensure_ascii=False)
                    misses = 0
                except ValueError as e:
                    #print(f" JSON invalide pour {code} — {e}")
                    misses += 1
            else:
                print(f"Miss: {code} - {r.status_code}")
                misses += 1
            i += 1
            time.sleep(sleep_between)

# Pour scrapper tous les avis à partir de 2023
scrap_RSS_items("avis", 2023, 392, folder="data/avis")

# Pour scrapper toutes les alertes à partir de 2021
scrap_RSS_items("alertes", 2021, 1, folder="data/alerte")

