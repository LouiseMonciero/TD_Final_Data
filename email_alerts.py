import smtplib
from email.mime.text import MIMEText
import json
import os
import time
from datetime import datetime, timedelta

# Liste des produits du client à surveiller
CLIENT_PRODUCTS = ["Linux"]
expediteur = "arthurleguillerme@gmail.com"
destinataire = "arthur.le-guillerme@efrei.net"
mot_de_passe = "bcwa husq nxtq mqlw"

def send_email(subject, body, to_email=destinataire):
    msg = MIMEText(body)
    msg['From'] = expediteur
    msg['To'] = destinataire
    msg['Subject'] = "alerte sécurité ANSSI"

    try:
        # Utilisation de SMTP_SSL sur le port 465
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(expediteur, mot_de_passe)
            server.sendmail(expediteur, destinataire, msg.as_string())
        print(f"[✓] Email envoyé à {to_email}")
    except Exception as e:
        print(f"[✗] Erreur lors de l'envoi du mail : {e}")

def produit_concerne(alert_data, produits_client):
    contenu = json.dumps(alert_data).lower()
    return any(prod.lower() in contenu for prod in produits_client)

def verifier_alertes_et_envoyer_emails(dossier_alertes="./data/avis"):
    maintenant = time.time()
    une_heure = 3600
    for fichier in os.listdir(dossier_alertes):
        if fichier.endswith(".json"):
            chemin = os.path.join(dossier_alertes, fichier)
            if os.path.isfile(chemin):
                # Vérifier si le fichier a été modifié il y a moins d'une heure                
                if maintenant - os.path.getmtime(chemin) < une_heure:
                    # Traiter l'alerte et envoyer le courrier électronique
                    with open(chemin, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    if produit_concerne(data, CLIENT_PRODUCTS):
                        titre = data.get("title", "Nouvelle alerte de sécurité ANSSI")
                        url = data.get("source", {}).get("url", "Lien non fourni")
                        corps = f"Alerte ANSSI détectée concernant vos produits :\n\nTitre : {titre}\nLien : {url}\n\nVeuillez vérifier au plus vite."

                        send_email(subject="Nouvelle alerte sécurité ANSSI", body=corps)
                        break

if __name__ == "__main__":
    verifier_alertes_et_envoyer_emails()
    print("[✓] Vérification des alertes terminée.")