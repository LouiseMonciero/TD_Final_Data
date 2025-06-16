import os
import json
import requests

def get_mitre_data(cve_id):
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()

        # Vérification minimale que la structure est conforme à MITRE v5.1
        if data.get("dataType") != "CVE_RECORD" or data.get("dataVersion") != "5.1":
            print(f"Structure inattendue pour {cve_id}")
            return

        # Création du dossier de destination si nécessaire
        os.makedirs("./data/mitre", exist_ok=True)
        path = f"./data/mitre/{cve_id}.json"

        # Sauvegarde brute du JSON
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=4)

        print(f"{cve_id} - Données sauvegardées (v5.1)")

    except requests.HTTPError as e:
        print(f"{cve_id} - Erreur HTTP : {e}")
    except Exception as e:
        print(f"{cve_id} - Erreur : {e}")
