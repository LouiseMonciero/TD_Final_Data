import requests
import os
import json

def get_first_data(cve_id):
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()

        if not data.get("data"):
            print(f"[!] Aucun résultat EPSS trouvé pour {cve_id}")
            return

        epss_entry = data["data"][0]
        epss_score = float(epss_entry.get("epss", 0))
        percentile = float(epss_entry.get("percentile", 0))
        date = epss_entry.get("date", "Non disponible")
        cve = epss_entry.get("cve", cve_id)

        # Résultat structuré
        result = {
            "cve_id": cve,
            "epss_score": epss_score,
            "percentile": percentile,
            "date": date
        }

        # Création d'un répertoire et enregistrement d'un fichier
        os.makedirs("./data/first", exist_ok=True)
        output_file = f"./data/first/{cve}.json"

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=4)

        print(f"Données de l'api first de {cve} enregistrées")

    except requests.exceptions.RequestException as e:
        print(f"Erreur réseau : {e}")
    except Exception as e:
        print(f"Erreur générale : {e}")
