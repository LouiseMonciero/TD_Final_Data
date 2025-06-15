import requests
import os
import json

def get_mitre_data(cve_id):
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()

        container = data.get("containers", {}).get("cna", {})

        description = container.get("descriptions", [{}])[0].get("value", "Non disponible")

        cvss_score = "Non disponible"
        try:
            metrics = container.get("metrics", [{}])
            for metric in metrics:
                for key in ["cvssV3_1", "cvssV3_0", "cvssV2"]:
                    if key in metric:
                        cvss_score = metric[key].get("baseScore", "Non disponible")
                        break
                if cvss_score != "Non disponible":
                    break
        except (KeyError, IndexError):
            pass

        cwe = "Non disponible"
        cwe_desc = "Non disponible"
        problemtypes = container.get("problemTypes", [])
        if problemtypes and "descriptions" in problemtypes[0]:
            cwe = problemtypes[0]["descriptions"][0].get("cweId", "Non disponible")
            cwe_desc = problemtypes[0]["descriptions"][0].get("description", "Non disponible")

        affected_list = []
        affected = container.get("affected", [])
        for product in affected:
            vendor = product.get("vendor", "Non disponible")
            product_name = product.get("product", "Non disponible")
            versions = [v.get("version") for v in product.get("versions", []) if v.get("status") == "affected"]
            affected_list.append({
                "vendor": vendor,
                "product": product_name,
                "versions": versions
            })

        result = {
            "cve_id": cve_id,
            "description": description,
            "cvss_score": cvss_score,
            "cwe_id": cwe,
            "cwe_description": cwe_desc,
            "affected_products": affected_list
        }

        os.makedirs("./data/mitre", exist_ok=True)
        with open(f"./data/mitre/{cve_id}.json", "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=4)

        print(f"Données de l'api mitre de {cve_id} enregistrées.")

    except requests.exceptions.RequestException as e:
        print(f"Erreur réseau : {e}")
    except Exception as e:
        print(f"Erreur générale : {e}")
