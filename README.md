# TD_Final_Data

Analyse des Avis et Alertes ANSSI avec Enrichissement des CVE

# Extraction des données

Les données RSS sont extraites grace au script **extracting_RSS.py**
Elle sont sauvegardés dans le dossier **data**
Une version plus complète et enrichie des données est disponible dans le dossier **data_pour_TD_final**

# Extraction des CVE

- Extrait tous les identifiants CVE présents dans les fichiers JSON du dossier **data/avis** grace au script **exctracting_cve_data.py**
- Pour chaque CVE trouvée, appelle les fonctions d’enrichissement pour récupérer les données MITRE et EPSS (voir ci-dessous).

# Extraction des API mitre et first

- Pour un identifiant CVE donné, télécharge les données détaillées depuis l’API officielle MITRE avec **extracting_mitre.py**
- De la même manière, on récupère le score EPSS via l’API FIRST avec **extracting_first.py**
- Sauvegarde la réponse JSON dans le dossier **data/mitre** et **data/first**.

# ALertes par email

- Surveille les fichiers d’alertes récents (moins d’une heure) dans le dossier **data/avis**.
- Si une alerte concerne un produit du client (défini dans `CLIENT_PRODUCTS`), envoie un email d’alerte avec le titre et le lien de l’alerte.
- Utilise les informations de connexion définies dans le dictionnaire `CREDENTIALS`.

# Consolidation des données en CSV

- Le script **consolidate_to_csv.py** parcourt tous les fichiers JSON des dossiers **data/avis** et **data/alertes**.
- Pour chaque bulletin, il extrait les informations principales (référence, titre, date, type, CVE, etc.).
- Pour chaque CVE, il enrichit les données avec les informations MITRE (description, score CVSS, gravité, CWE, produits affectés) et le score EPSS (FIRST).
- Les données consolidées sont organisées ligne par ligne (une ligne par produit/version affecté) et exportées dans **data/data.csv**
