import smtplib
from email.mime.text import MIMEText
import json
import os
import time
from datetime import datetime, timedelta

# Liste des produits du client à surveiller, ici juste linux pour l'exemple
CLIENT_PRODUCTS = ["Linux"]

# Coordonnées et mot de passe pour l'envoi d'email
CREDENTIALS = {
    "expediteur": "adresse expéditeur",
    "destinataire": "adresse destinataire",
    "mot_de_passe": "mot de passe de l'expéditeur"
}

def send_email(subject, body):
    """
    Envoie un email avec le sujet et le corps spécifiés.
    Utilise les informations de CREDENTIALS pour l'expéditeur et le destinataire.
    """
    expediteur = CREDENTIALS["expediteur"]
    destinataire = CREDENTIALS["destinataire"]
    mot_de_passe = CREDENTIALS["mot_de_passe"]
    msg = MIMEText(body)
    msg['From'] = expediteur
    msg['To'] = destinataire
    msg['Subject'] = "alerte sécurité ANSSI"

    try:
        # Connexion sécurisée au serveur SMTP de Gmail
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(expediteur, mot_de_passe)
            server.sendmail(expediteur, destinataire, msg.as_string())
        print(f"[✓] Email envoyé")
    except Exception as e:
        print(f"[✗] Erreur lors de l'envoi du mail : {e}")

def produit_concerne(alert_data, produits_client):
    """
    Vérifie si l'un des produits du client est mentionné dans l'alerte.
    """
    contenu = json.dumps(alert_data).lower()
    return any(prod.lower() in contenu for prod in produits_client)

def verifier_alertes_et_envoyer_emails(dossier_alertes="./data/avis"):
    """
    Parcourt les fichiers d'alertes récents (moins d'une heure) dans le dossier donné.
    Si une alerte concerne un produit du client, envoie un email avec les détails.
    """
    maintenant = time.time()
    une_heure = 360000
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
                        url = data["links"][0].get("url")
                        corps = f"Alerte ANSSI détectée concernant vos produits :\n\nTitre : {titre}\nLien : {url}\n\nVeuillez vérifier au plus vite."

                        send_email(subject="Nouvelle alerte sécurité ANSSI", body=corps)
                        break # Sortir après le premier email envoyé pour ne pas recevoir plusieurs mails d'un seul coup

if __name__ == "__main__":
    verifier_alertes_et_envoyer_emails()
    print("[✓] Vérification des alertes terminée.")