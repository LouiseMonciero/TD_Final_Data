import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Data loading
df = pd.read_csv('data/data.csv')

# 1. Histogram of severity levels (based on CVSS)

# Severity level categorization function
def cvss_to_severity(score):
    try:
        score = float(score)
        if score <= 3:
            return 'Faible'
        elif score <= 6:
            return 'Moyenne'
        elif score <= 8:
            return 'Élevée'
        else:
            return 'Critique'
    except:
        return 'Inconnu'

df['Gravité'] = df['CVSS'].apply(cvss_to_severity)
grav_counts = df['Gravité'].value_counts().reindex(['Faible', 'Moyenne', 'Élevée', 'Critique', 'Inconnu'], fill_value=0)

# Plot
plt.figure(figsize=(8,5))
grav_counts.plot(kind='bar', color=['green', 'orange', 'red', 'darkred', 'gray'])
plt.title('Histogramme des niveaux de gravité des vulnérabilités (CVSS)')
plt.xlabel('Niveau de gravité')
plt.ylabel('Nombre de vulnérabilités')
plt.tight_layout()
plt.savefig("Visualisation/histogramme_gravite.png")
plt.show()

# 2. Circular vulnerability diagram (CWE)

# Data cleaning
df['CWE'] = df['CWE'].fillna('Inconnu')

# Top 8 most frequents, the other gouped by "Others"
top_cwe = df['CWE'].value_counts()
top_8 = top_cwe.head(8)
autres = top_cwe[8:].sum()
top_8['Autres'] = autres

# Plot
plt.figure(figsize=(8,8))
top_8.plot(kind='pie', autopct='%1.1f%%', startangle=140)
plt.title('Répartition des types de vulnérabilités (CWE)')
plt.ylabel('')
plt.tight_layout()
plt.savefig("Visualisation/camembert_CWE.png")
plt.show()

# 3. EPSS Score Density Curve

# Ensure EPSS scores are numeric
df['EPSS'] = pd.to_numeric(df['EPSS'], errors='coerce')
epss_valid = df['EPSS'].dropna()

# Plot
plt.figure(figsize=(8, 5))
sns.kdeplot(epss_valid, fill=True, color="purple", alpha=0.6)
plt.title('EPSS score distribution')
plt.xlabel('EPSS Score')
plt.ylabel('Density')
plt.tight_layout()
plt.savefig("Visualisation/epss_curve.png")
plt.show()

# 4. Top Affected editors

# Count top 10 most frequently affected editors
top_editors = df['Éditeur'].value_counts().head(10)


# Plot horizontal bar chart
plt.figure(figsize=(10, 5))
top_editors.plot(kind='barh', color='steelblue')
plt.title('Top 10 éditeurs les plus affectés')
plt.xlabel('Nombre de vulnérabilités')
plt.gca().invert_yaxis()
plt.tight_layout()
plt.savefig("Visualisation/top_affected_products.png")
plt.show()