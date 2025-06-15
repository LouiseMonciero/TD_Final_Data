import os
import json
import re

# Importation des fonctions à partir des autres fichiers
from extracting_mitre import get_mitre_data
from extracting_first import get_first_data

def extract_cves_from_avis():
    all_cves = set()
    avis_folder = "./data/avis"

    for filename in os.listdir(avis_folder):
        if filename.endswith(".json"):
            filepath = os.path.join(avis_folder, filename)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    data = json.load(f)

                # Extraction via clé "cves"
                if "cves" in data:
                    for cve_item in data["cves"]:
                        name = cve_item.get("name")
                        if name and name.startswith("CVE-"):
                            all_cves.add(name)

                # Extraction via regex
                content_str = json.dumps(data)
                found = re.findall(r"CVE-\d{4}-\d{4,7}", content_str)
                all_cves.update(found)

            except Exception as e:
                print(f"[!] Erreur lecture {filename} : {e}")

    return sorted(all_cves)

def run_full_pipeline():
    cve_ids = extract_cves_from_avis()
    print(f"\n{len(cve_ids)} CVE identifiées : {cve_ids}\n")
    for cve_id in cve_ids:
        get_mitre_data(cve_id)
        get_first_data(cve_id)


run_full_pipeline()