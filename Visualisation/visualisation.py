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

# Plot
plt.figure(figsize=(10, 5))
top_editors.plot(kind='barh', color='steelblue')
plt.title('Top 10 éditeurs les plus affectés')
plt.xlabel('Nombre de vulnérabilités')
plt.gca().invert_yaxis()
plt.tight_layout()
plt.savefig("Visualisation/top_affected_editors.png")
plt.show()

# 5. Top affected products

# Count top 10 most frequently affected products
top_products = df['Produit'].value_counts().head(10)

# Plot
plt.figure(figsize=(10, 5))
top_products.plot(kind='barh', color='steelblue')
plt.title('Top 10 produits les plus affectés')
plt.xlabel('Nombre de vulnérabilités')
plt.gca().invert_yaxis()
plt.tight_layout()
plt.savefig("Visualisation/top_affected_products.png")
plt.show()

# 6. Heatmap : Correlation between CVSS and EPSS

df["CVSS"] = pd.to_numeric(df["CVSS"], errors="coerce")

# Create a correlation dataframe
correlation_df = df[["CVSS", "EPSS"]].dropna()

df["Gravité_CVSS"] = df["CVSS"].apply(cvss_to_severity)

# Categorize EPSS into 4 probability bins
def epss_to_level(epss):
    if epss <= 0.25:
        return "Faible"
    elif epss <= 0.5:
        return "Moyenne"
    elif epss <= 0.75:
        return "Élevée"
    else:
        return "Critique"
    
df["Probabilité_EPSS"] = df["EPSS"].apply(epss_to_level)

# Create cross-tab
heatmap_data = pd.crosstab(df["Gravité_CVSS"], df["Probabilité_EPSS"])

# Reorder for visual consistency
heatmap_data = heatmap_data.reindex(index=["Critique", "Élevée", "Moyenne", "Faible"],
                                     columns=["Faible", "Moyenne", "Élevée", "Critique"])

# Plot heatmap
plt.figure(figsize=(7, 5))
sns.heatmap(heatmap_data, annot=True, fmt="d", cmap="coolwarm")
plt.title("Relation entre gravité CVSS et probabilité EPSS")
plt.xlabel("Probabilité d'exploitation (EPSS)")
plt.ylabel("Niveau de gravité (CVSS)")
plt.tight_layout()
plt.savefig("Visualisation/heatmap_cvss_vs_epss.png")
plt.show()

# 7. Scatter plot : CVSS vs EPSS

plt.figure(figsize=(8, 5))
sns.scatterplot(data=df, x="CVSS", y="EPSS", alpha=0.6, color="teal")
plt.title("Nuage de points : Score CVSS vs Score EPSS")
plt.xlabel("Score CVSS")
plt.ylabel("Score EPSS")
plt.tight_layout()
plt.savefig("Visualisation/scatter_cvss_epss.png")
plt.show()

# _. Cumulative curve: Vulnerabilities over time

# Convert Date to datetime
#df["Date"] = pd.to_datetime(df["Date"], errors="coerce")
df_sorted = df.sort_values("Date").dropna(subset=["Date"])

# Group by date and calculate cumulative sum
cumulative_df = df_sorted.groupby("Date").size().cumsum()

# Plot
plt.figure(figsize=(10, 5))
cumulative_df.plot(color="darkblue")
plt.title("Evolution dans le temps du nombre de vulnérabilités")
plt.xlabel("Date")
plt.ylabel("Nombre cumulatif de vulnérabilités")
plt.tight_layout()
plt.savefig("Visualisation/courbe_cumulative_temps.png")
plt.show()