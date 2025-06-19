# TD_Final_Data

Analyse des bulletins ANSSI enrichis par les données CVE, MITRE et EPSS.

# Prérequis

Avant de lancer l’application, assurez-vous d’avoir installé les dépendances suivantes (via pip ou conda) :

``pip install pandas matplotlib seaborn scikit-learn xgboost imbalanced-learn requests``

# Lancement manuel du projet

### Extraction des données ANSSI

On vous déconseille quand même de lancer cette partie du projet puisqu'elle consiste à la récupération des données du site qui nous a mis plusieurs heures à scraper.

``python extracting_RSS.py``

### Extraction des CVE depuis les bulletins et enrichissement via API MITRE et FIRST

``python extracting_cve_data.py``

### Consolidation dans un fichier CSV

``python consolidate_to_csv.py``

### Visualisation et modèles machine learning

Pour lancer cette partie, il faut lancer le notebook.

### Génération d'alertes

``email_alerts.py``

# Points de vigilence

- Les bulletins « Alertes » ne sont disponibles qu’à partir de 2021, les « Avis » à partir de 2023.

- Les appels aux APIs MITRE et EPSS peuvent être lents ou échouer si trop fréquents. Prévois des pauses si nécessaire (time.sleep() intégré dans les scripts).

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

# Visualisation et analyse (Notebook)

Le fichier analyse_notebook.ipynb contient :

- Le chargement du fichier data.csv

- Le pre-processing de la data

- Plusieurs visualisations (boxplots, heatmaps, nuages de points…)

- Des modèles de machine learning : supervisés (Random Forest et XGBoost)et non supervisé (KMeans)

- Évaluation des performances (précision, validation croisée…)

Le notebook est également fourni en HTML pour une lecture directe sans exécution.
