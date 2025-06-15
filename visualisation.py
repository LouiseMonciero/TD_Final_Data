import pandas as pd
import matplotlib.pyplot as plt

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
plt.savefig("histogramme_gravite.png")
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
plt.savefig("camembert_CWE.png")
plt.show()