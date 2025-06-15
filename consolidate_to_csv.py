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
    rows = []  # list that collects each row of the future CSV
    mitre_dir = "./data/mitre"
    first_dir = "./data/first"
    bulletins_dirs = [
        ("./data/avis", "Avis"),
        ("./data/alertes", "Alerte")
    ]

    for folder_path, type_bulletin in bulletins_dirs:
        for filename in os.listdir(folder_path):
            if not filename.endswith(".json"):
                continue

            with open(os.path.join(folder_path, filename), encoding="utf-8") as f:
                bulletin = json.load(f)

            id_anssi = bulletin.get("reference", "")
            titre = bulletin.get("title", "")
            revisions = bulletin.get("revisions", [])
            date = ""
            for rev in revisions:
                if rev.get("description", "").lower().startswith("version initiale"):
                    date = rev.get("revision_date", "")
                    break
            if not date and revisions:
                date = revisions[0].get("revision_date", "")
            lien = bulletin.get("url", "")

            cve_list = []
            if "cves" in bulletin:
                cve_list = [c.get("name") for c in bulletin["cves"] if c.get("name", "").startswith("CVE-")]

            for cve in cve_list:
                # load CVE data from MITRE
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

                # load CVE data from EPSS (FIRST)
                epss = ""
                epss_path = os.path.join(first_dir, f"{cve}.json")
                if os.path.exists(epss_path):
                    with open(epss_path, encoding="utf-8") as f:
                        epss_data = json.load(f)
                        epss = epss_data.get("epss_score", "")

                for produit in affected:  # 1 row = 1 affected product-version
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

    # convert into a DataFrame and export to CSV
    df = pd.DataFrame(rows)
    os.makedirs("data", exist_ok=True)
    df.to_csv("data/data.csv", index=False, encoding="utf-8")

if __name__ == "__main__":
    consolidate_data()
