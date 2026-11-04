# AIT-ADS — données du projet

Source officielle : [AIT-ADS sur Zenodo](https://zenodo.org/records/8263181), DOI 10.5281/zenodo.8263181.

- `ait_ads.zip` : journaux d’alertes multi-détecteurs, organisés par scénario.
- `labels.csv` : fenêtres temporelles des phases d’attaque.

Le pipeline de démonstration extrait les scénarios `shaw`, `wardbeck` et `russellmitchell`. Les deux premiers servent à l’entraînement et au choix du seuil ; le dernier est gardé pour le test final.

**Limite des annotations :** `labels.csv` indique des fenêtres de phase, pas des relations confirmées par analyste entre deux alertes. Les labels de paires produits dans ce projet sont faibles : les deux alertes doivent tomber dans une fenêtre d’attaque du même scénario.
