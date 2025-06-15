import feedparser
import ssl
import time
import requests
import os
import json
import random

url = "https://cert.ssi.gouv.fr/avis/feed/"

if hasattr(ssl, '_create_unverified_context'):
    ssl._create_default_https_context = ssl._create_unverified_context
rss_feed = feedparser.parse(url)
#print(len(rss_feed.entries))

for i in range(0, len(rss_feed.entries)):

    url_avis = rss_feed.entries[i].link
    response = requests.get(url_avis.rstrip('/') + '/json/')

    if response.status_code == 200:
        avis_json = response.json()

        reference = avis_json.get("reference", "avis_sans_ref")

        os.makedirs("./data/avis", exist_ok=True)

        with open(f"./data/avis/{reference}.json", "w", encoding='utf-8') as f:
            json.dump(avis_json, f, ensure_ascii=False, indent=4)
    else:
        print(f"Erreur lors de l'accès au JSON : {response.status_code} – {response.text}")

    time.sleep(random.randint(90, 140)) if (i%7 == 0) else time.sleep(random.randint(3, 8))
    i+=1
    print(i)
print(i)

url_alerte = "https://cert.ssi.gouv.fr/alerte/feed/"
rss_feed_alerte = feedparser.parse(url_alerte)


for i in range(0, len(rss_feed_alerte.entries)):
    url = rss_feed_alerte.entries[i].link
    response = requests.get(url.rstrip('/') + '/json/')

    if response.status_code == 200:
        alerte_json = response.json()
        reference = alerte_json.get("reference", "alerte_sans_ref")
        os.makedirs("./data/alertes", exist_ok=True)
        with open(f"./data/alertes/{reference}.json", "w", encoding='utf-8') as f:
            json.dump(alerte_json, f, ensure_ascii=False, indent=4)
    else:
        print(f"Erreur lors de l'accès au JSON (alerte) : {response.status_code} – {response.text}")

    time.sleep(random.randint(90, 140)) if (i % 7 == 0) else time.sleep(random.randint(3, 8))
    