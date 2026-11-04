# Corrélation bayésienne d'alertes IDS

Prototype interprétable et reproductible de corrélation d'alertes provenant de plusieurs outils de détection d'intrusion. Le projet utilise le jeu de données [AIT-ADS](https://zenodo.org/records/8263181) pour normaliser des alertes hétérogènes, générer des paires candidates à partir de l'historique, estimer leur probabilité de corrélation avec un modèle Beta-Bernoulli et évaluer des alertes en flux.

> **Périmètre :** il s'agit d'un prototype exploratoire. Les annotations utilisées sont dérivées de fenêtres temporelles d'attaque et ne représentent pas des liens confirmés par un analyste entre deux alertes.

## 1. Présentation du projet

Les plateformes de supervision produisent souvent de nombreuses alertes provenant de détecteurs différents. Ce projet étudie si des caractéristiques temporelles et contextuelles permettent d'identifier les alertes appartenant à une même phase d'attaque :

- normalisation des alertes AMiner et Wazuh, y compris les événements liés à Suricata ;
- conservation de l'horodatage, du détecteur, de l'hôte, de la signature, de la sévérité et du message ;
- génération d'un nombre limité de paires candidates à partir de l'historique ;
- estimation de probabilités interprétables par mise à jour bayésienne ;
- sélection d'un seuil de décision sur les scénarios d'entraînement ;
- calcul d'un score pour de nouvelles alertes à partir de l'historique récent.

Le code du modèle utilise uniquement la bibliothèque standard Python. Matplotlib est utilisé par les notebooks pour les visualisations.

## 2. Chaîne de traitement

```text
Archive AIT-ADS + fenêtres de phases d'attaque
                  |
                  v
1_Preprocessing.ipynb
  Normalisation des alertes et association des fenêtres
                  |
                  v
normalized_alerts.csv
                  |
                  v
2_Data_Modeling_Validation.ipynb
  Paires candidates, modèle Beta-Bernoulli,
  sélection du seuil et validation sur un scénario séparé
                  |
                  v
bayesian_alert_correlation_model.json
validation_metrics.json
                  |
                  v
3_Model_Serving.ipynb
  Score des nouvelles alertes par rapport à l'historique
```

## 3. Jeu de données

Le projet utilise **AIT-ADS (AIT Alert Dataset)**, disponible sur [Zenodo](https://zenodo.org/records/8263181).

Après téléchargement, placer l'archive à l'emplacement suivant :

```text
data/AIT-ADS/ait_ads.zip
```

Le dépôt contient `data/AIT-ADS/labels.csv` et la documentation du jeu de données, mais exclut l'archive volumineuse du contrôle de version. Les notebooks utilisent trois scénarios :

- `shaw` et `wardbeck` pour l'entraînement et la sélection du seuil ;
- `russellmitchell` comme scénario final tenu à l'écart.

Les annotations indiquent des fenêtres temporelles associées aux attaques. Elles ne fournissent pas de relations indépendantes et confirmées par un analyste entre les alertes.

## 4. Méthode

Pour chaque alerte, le modèle compare un historique récent borné et extrait cinq indicateurs binaires :

- même hôte ;
- même détecteur ;
- même signature ;
- écart temporel inférieur ou égal à 10 secondes ;
- écart temporel inférieur ou égal à 60 secondes.

Pour les classes de paires positives et négatives, le modèle estime la probabilité de chaque caractéristique avec un a priori uniforme `Beta(1, 1)` et une vraisemblance de Bernoulli. La génération des candidats ne dépend pas des labels et reste bornée par :

- 50 alertes historiques au maximum ;
- un âge maximal de 30 minutes ;
- 5 candidats diversifiés au maximum par alerte.

Le label d'une paire est un proxy faible : les deux alertes doivent se trouver dans une fenêtre d'attaque du même scénario. Il ne doit pas être interprété comme une relation d'incident confirmée.

## 5. Résultats

L'artefact de validation versionné fournit les résultats exploratoires suivants sur `russellmitchell` :

| Mesure | Valeur |
|---|---:|
| Seuil de décision | 0.04 |
| Paires candidates | 102 667 |
| Précision | 0.337 |
| Rappel | 0.934 |
| Score F1 | 0.495 |
| Average precision | 0.681 |
| ROC AUC | 0.680 |

Ces valeurs mesurent l'accord avec le proxy dérivé des phases d'attaque. Elles ne mesurent ni la qualité de liens confirmés par des analystes ni les performances d'un système de détection en production.

## 6. Structure du dépôt

```text
.
|-- artifacts/
|   `-- alert_correlation/
|       |-- bayesian_alert_correlation_model.json
|       `-- validation_metrics.json
|-- data/
|   `-- AIT-ADS/
|       |-- labels.csv
|       `-- README.md
|-- docs/
|   `-- PROJECT_WORKFLOW.md
|-- notebooks/
|   |-- 1_Preprocessing.ipynb
|   |-- 2_Data_Modeling_Validation.ipynb
|   `-- 3_Model_Serving.ipynb
|-- src/
|   `-- alert_correlation/
|       |-- __init__.py
|       `-- core.py
|-- .gitignore
|-- README.md
`-- requirements.txt
```

Les supports de présentation et les captures associées sont volontairement exclus du dépôt public. Ils ne sont pas nécessaires pour reproduire le pipeline ; les notebooks, le code source, les métriques et la documentation constituent les livrables techniques.

## 7. Prérequis

- Python 3.9 ou version ultérieure ;
- Jupyter Notebook ou JupyterLab ;
- l'archive AIT-ADS téléchargée depuis Zenodo ;
- les dépendances listées dans `requirements.txt`.

Créer un environnement virtuel et installer les dépendances :

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Sous Linux ou macOS :

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## 8. Reproduire le pipeline

Lancer Jupyter depuis la racine du dépôt :

```bash
jupyter lab
```

Exécuter les notebooks dans l'ordre :

1. `notebooks/1_Preprocessing.ipynb`
2. `notebooks/2_Data_Modeling_Validation.ipynb`
3. `notebooks/3_Model_Serving.ipynb`

Le premier notebook régénère `artifacts/alert_correlation/normalized_alerts.csv`, ignoré par Git car il peut être reconstruit à partir du jeu de données. Le deuxième notebook régénère le modèle et les métriques ; les fichiers JSON versionnés fournissent une exécution de référence. Le troisième notebook illustre le calcul de scores en ligne à partir de l'historique récent.

## 9. API Python

L'implémentation commune se trouve dans [`src/alert_correlation/core.py`](src/alert_correlation/core.py). Les fonctions principales sont :

- `preprocess_ait_ads(...)` : normalisation et association des fenêtres de phases ;
- `load_alerts(...)` : chargement des alertes normalisées ;
- `pair_features(...)` : extraction des indicateurs de corrélation ;
- `iter_candidate_pairs(...)` : génération bornée des paires candidates ;
- `select_history_candidates(...)` : sélection de candidats diversifiés dans l'historique.

Le module n'a pas de dépendance externe et peut être importé directement depuis la racine du dépôt.

## 10. Limites et interprétation

- Le projet est un prototype de recherche et de démonstration, pas un moteur SIEM de production.
- Les labels sont des labels faibles issus de fenêtres d'attaque, et non des relations confirmées par un analyste.
- Trois scénarios AIT-ADS seulement sont utilisés, dont un réservé à la démonstration finale.
- Le modèle suppose l'indépendance conditionnelle des caractéristiques binaires connaissant la classe de la paire.
- Le notebook de mise en service utilise un historique en mémoire et ne fournit ni persistance, ni déduplication, ni boucle de retour analyste.
- Les résultats ne doivent pas être généralisés à d'autres environnements sans scénarios supplémentaires et vérité terrain indépendante.

## 11. Référence

Landauer, M., Skopik, F. et Wurzenberger, M. **AIT-ADS: A Dataset for Intrusion Detection and Alert Correlation**. [AIT-ADS sur Zenodo](https://zenodo.org/records/8263181).

## 12. Documentation

- [Guide du workflow](docs/PROJECT_WORKFLOW.md)
- [Documentation du jeu de données](data/AIT-ADS/README.md)
