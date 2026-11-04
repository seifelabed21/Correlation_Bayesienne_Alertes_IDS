# Guide de workflow — corrélation bayésienne d’alertes IDS

## Objectif

Le projet étudie si des alertes émises par plusieurs détecteurs peuvent être rapprochées dans le temps pour faire émerger un contexte d’attaque. Il utilise **AIT-ADS**, conçu pour l’agrégation et la corrélation d’alertes. CICIDS2017 reste archivé comme ancien travail sur des flux : un flux réseau et une alerte IDS sont des objets différents.

**Limite centrale à annoncer :** AIT-ADS annote des fenêtres/phases d’attaque, mais ne fournit pas de liens vérifiés par analyste entre chaque paire d’alertes. Notre cible est donc un label faible (« les deux alertes sont dans une fenêtre d’attaque »). Les scores mesurent l’accord avec ce proxy, et non la qualité de liens analyste-confirmés.

## Équipe et responsabilités

| Étape | Notebook | Responsable | Rôle |
|---|---|---|---|
| 1. Prétraitement | `1_Preprocessing.ipynb` | **Mohamed Omezzine** | Normaliser les journaux multi-détecteurs, conserver le temps et le contexte, joindre les fenêtres de phases. |
| 2. Modélisation et validation | `2_Data_Modeling_Validation.ipynb` | **Seifeddine El Abed** | Construire des paires candidates depuis l’historique, estimer leurs probabilités et évaluer sur un scénario gardé à part. |
| 3. Mise en service | `3_Model_Serving.ipynb` | **Mouheb Jouili** | Charger le modèle, traiter les alertes en flux et renvoyer les alertes rapprochées et leurs scores. |

## Vue d’ensemble

```text
AIT-ADS (alertes AMiner, Wazuh et Suricata + fenêtres de phases)
             │
             ▼
1_Preprocessing.ipynb — Mohamed Omezzine
             │  artifacts/alert_correlation/normalized_alerts.csv
             ▼
2_Data_Modeling_Validation.ipynb — Seifeddine El Abed
  paires depuis l’historique → features → posterior Beta–Bernoulli
             │  modèle JSON + mesures sur russellmitchell
             ▼
3_Model_Serving.ipynb — Mouheb Jouili
  nouvelle alerte → comparaison à l’historique → liens scorés
```

## Jeu de données

Le projet utilise **AIT-ADS** (AIT Alert Dataset), disponible sur [Zenodo](https://zenodo.org/records/8263181). Il contient plusieurs scénarios multi-étapes et des journaux associés à plusieurs détecteurs. Les fichiers livrés dans `data/AIT-ADS/` sont `ait_ads.zip` et `labels.csv`.

La démonstration utilise trois scénarios : `shaw`, `wardbeck` et `russellmitchell`. `shaw` et `wardbeck` servent à l’entraînement et au choix du seuil par validation croisée au niveau scénario ; `russellmitchell` est réservé au test final. Ce test unique est utile pour une démonstration, mais ne suffit pas pour généraliser à tous les réseaux ou tous les scénarios.

## Modules et contrats de données

### 1. Prétraitement — `1_Preprocessing.ipynb`

Lit les JSON des scénarios sélectionnés dans l’archive et joint `labels.csv`. Il uniformise l’heure, le détecteur, l’hôte, la signature, la sévérité et le message.

**Sortie :** `artifacts/alert_correlation/normalized_alerts.csv` avec `scenario`, `event_id`, `timestamp_epoch`, `timestamp_utc`, `detector`, `host`, `signature`, `severity`, `message`, `attack_phase` et `is_attack`.

`attack_phase` / `is_attack` proviennent des fenêtres du dataset. Ils ne représentent pas un jugement humain indépendant sur une paire.

### 2. Modélisation et validation — `2_Data_Modeling_Validation.ipynb`

Les alertes sont triées par scénario et par temps. Chaque nouvelle alerte est comparée à un historique borné (jusqu’à 50 alertes, 30 minutes) avec quelques candidates diverses. Les cinq indices binaires sont : même hôte, même détecteur, même signature, intervalle inférieur ou égal à 10 secondes, intervalle inférieur ou égal à 60 secondes.

Pour chaque indice binaire et classe de paire, le modèle utilise une loi Beta avec prior uniforme `Beta(1,1)`, conjuguée à une vraisemblance de Bernoulli. Le calcul est analytique (pas de MCMC). La prédiction naïve suppose les indices indépendants sachant la classe.

Une paire positive signifie uniquement que **ses deux alertes sont dans les fenêtres d’attaque du même scénario**. Le seuil est sélectionné sur des prédictions hors-échantillon au niveau scénario, dans les scénarios d’entraînement seulement.

**Artefacts :**

- `artifacts/alert_correlation/bayesian_alert_correlation_model.json`
- `artifacts/alert_correlation/validation_metrics.json`

Les mesures sont précision, rappel, F1, average precision, ROC AUC et matrice de confusion. Elles évaluent le proxy faible et ne démontrent pas des liens analyste-confirmés.

### 3. Mise en service — `3_Model_Serving.ipynb`

Charge le JSON et crée un scoreur d’alertes en ligne. Chaque alerte normalisée est comparée à un historique récent ; le service retourne son identifiant, le seuil, la probabilité maximale et les identifiants des alertes candidates dépassant le seuil.

Le notebook montre un flux de démonstration issu du scénario de test. Les labels servent uniquement à choisir un extrait lisible, puis sont retirés avant le scoreur. Un système réel demanderait une persistance de l’historique et une validation par analyste.

## Lancement

Depuis le dossier `ids`, exécuter les notebooks dans l’ordre :

1. `1_Preprocessing.ipynb`
2. `2_Data_Modeling_Validation.ipynb`
3. `3_Model_Serving.ipynb`

Le code commun est dans `alert_correlation/core.py`. Les anciennes versions orientées flux sont conservées dans `legacy_cicids2017_flow/` pour référence ; elles ne font pas partie du pipeline AIT-ADS.

## Message raisonnable pour la soutenance

> « Nous avons construit un prototype qui estime la compatibilité de paires d’alertes à partir de l’historique et de quelques indices temporels et contextuels. Il calcule effectivement des scores. Leur validation reste exploratoire, car les annotations disponibles indiquent des fenêtres d’attaque plutôt que des relations vraies entre alertes. »

## Référence

Landauer, M., Skopik, F. & Wurzenberger, M. **AIT-ADS: A Dataset for Intrusion Detection and Alert Correlation**, [dataset AIT-ADS sur Zenodo](https://zenodo.org/records/8263181).
