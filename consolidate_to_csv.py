import os
import json
import pandas as pd

# convert CVSS score to severity level
def gravite_from_cvss(cvss):
    if cvss is None or cvss == "Non disponible":
        return None
    try:
        cvss = float(cvss)
        if cvss >= 9.0:
            return "Critique"
        elif cvss >= 7.0:
            return "Élevée"
        elif cvss >= 4.0:
            return "Moyenne"
        else:
            return "Faible"
    except:
        return None


def consolidate_data():
    rows = [] # list that collect each row of the future CSV
    avis_dir = "./data/avis"
    mitre_dir = "./data/mitre"
    first_dir = "./data/first"

    for filename in os.listdir(avis_dir):
        if not filename.endswith(".json"):
            continue

        with open(os.path.join(avis_dir, filename), encoding="utf-8") as f:
            avis_data = json.load(f)

        # extract ANSSI metadata
        id_anssi = avis_data.get("reference", "")
        titre = avis_data.get("title", "")
        type_bulletin = "Alerte" if "alerte" in id_anssi.lower() else "Avis"
        date = avis_data.get("initial_release_date", "")
        lien = avis_data.get("url", "")

        cve_list = []
        if "cves" in avis_data:
            cve_list = [c.get("name") for c in avis_data["cves"] if c.get("name", "").startswith("CVE-")]

        for cve in cve_list:
            # load CVE data from mitre
            mitre_path = os.path.join(mitre_dir, f"{cve}.json")
            if not os.path.exists(mitre_path):
                continue
            with open(mitre_path, encoding="utf-8") as f:
                mitre = json.load(f)

            description = mitre.get("description", "")
            cvss = mitre.get("cvss_score", None)
            cwe = mitre.get("cwe_id", "Non disponible")
            gravite = gravite_from_cvss(cvss)

            affected = mitre.get("affected_products", [])
            if not affected:
                affected = [{"vendor": "", "product": "", "versions": []}]

            # load CVE data from first
            epss = ""
            epss_path = os.path.join(first_dir, f"{cve}.json")
            if os.path.exists(epss_path):
                with open(epss_path, encoding="utf-8") as f:
                    epss_data = json.load(f)
                    epss = epss_data.get("epss_score", "")

            for produit in affected: # 1 row = 1 affected product-version
                rows.append({
                    "ID_ANSSI": id_anssi,
                    "Titre": titre,
                    "Type": type_bulletin,
                    "Date": date,
                    "CVE": cve,
                    "CVSS": cvss,
                    "Base Severity": gravite,
                    "CWE": cwe,
                    "EPSS": epss,
                    "Lien": lien,
                    "Description": description,
                    "Éditeur": produit.get("vendor", ""),
                    "Produit": produit.get("product", ""),
                    "Versions affectées": ", ".join(produit.get("versions", []))
                })

    # convert into a data frame and export to CSV
    df = pd.DataFrame(rows)
    os.makedirs("data", exist_ok=True)
    df.to_csv("data/data.csv", index=False, encoding="utf-8")
    print("Le fichier data.csv a été généré avec succès")

if __name__ == "__main__":
    consolidate_data()
