# Bayesian Alert Correlation for Intrusion Detection

An interpretable, reproducible baseline for correlating alerts from multiple intrusion-detection tools. The project uses the [AIT-ADS dataset](https://zenodo.org/records/8263181) to normalize heterogeneous alerts, generate bounded historical candidate pairs, estimate correlation probabilities with a Beta-Bernoulli model, and score incoming alerts in a streaming-style demonstration.

> **Scope:** This is an exploratory alert-correlation prototype. Its labels are derived from attack-phase time windows in AIT-ADS and do not represent analyst-confirmed links between individual alerts.

## 1. Project Overview

Security monitoring platforms often produce many alerts from different detectors. This project explores whether observable context can help identify alerts that belong to the same attack phase:

- normalize alerts from AMiner, Wazuh, and Suricata-related records;
- preserve time, detector, host, signature, severity, and message context;
- generate a small, bounded set of historical candidate pairs;
- learn interpretable feature probabilities with Bayesian updating;
- select a decision threshold on training scenarios only;
- score new alerts against recent history.

The implementation is deliberately lightweight: the model code uses Python's standard library, while Matplotlib is used by the notebooks for visual analysis.

## 2. Processing Pipeline

```text
AIT-ADS archive + phase labels
            |
            v
1_Preprocessing.ipynb
  Normalize detector records and attach phase windows
            |
            v
normalized_alerts.csv
            |
            v
2_Data_Modeling_Validation.ipynb
  Build candidate pairs, fit Beta-Bernoulli model,
  select threshold, evaluate on a held-out scenario
            |
            v
bayesian_alert_correlation_model.json
validation_metrics.json
            |
            v
3_Model_Serving.ipynb
  Score incoming alerts against recent history
```

## 3. Dataset

The project uses **AIT-ADS (AIT Alert Dataset)** from [Zenodo](https://zenodo.org/records/8263181).

Download the archive and place it at:

```text
data/AIT-ADS/ait_ads.zip
```

The repository includes `data/AIT-ADS/labels.csv` and the dataset documentation, but excludes the large archive from version control. The notebooks use three scenarios:

- `shaw` and `wardbeck` for training and threshold selection;
- `russellmitchell` as a held-out final demonstration scenario.

The phase annotations indicate time windows associated with attacks. They do not provide independent, analyst-confirmed relationships between pairs of alerts.

## 4. Method

For each alert, the model compares a bounded recent history and extracts five binary indicators:

- same host;
- same detector;
- same signature;
- time gap of at most 10 seconds;
- time gap of at most 60 seconds.

The model estimates each feature probability for positive and negative pair classes using a uniform `Beta(1, 1)` prior and a Bernoulli likelihood. Candidate generation is label-independent and bounded to:

- up to 50 historical alerts;
- a maximum age of 30 minutes;
- up to 5 diverse candidates per alert.

The current pair label is a weak proxy: both alerts must fall inside an attack-phase window of the same scenario. It should not be interpreted as a confirmed incident relationship.

## 5. Results

The committed validation artifact reports the following exploratory results on `russellmitchell`:

| Metric | Value |
|---|---:|
| Decision threshold | 0.04 |
| Candidate pairs | 102,667 |
| Precision | 0.337 |
| Recall | 0.934 |
| F1 score | 0.495 |
| Average precision | 0.681 |
| ROC AUC | 0.680 |

These values measure agreement with the phase-derived proxy labels. They do not measure analyst-confirmed alert-link quality or production detection performance.

## 6. Repository Structure

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
|   |-- PRESENTATION_PLAN.md
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

The presentation directory is intentionally excluded from the public repository. Presentation slides and screenshots are not required to reproduce the pipeline; the notebooks, source code, metrics, and documentation are the project deliverables.

## 7. Requirements

- Python 3.9 or later;
- Jupyter Notebook or JupyterLab;
- the AIT-ADS archive downloaded from Zenodo;
- dependencies listed in `requirements.txt`.

Install the dependencies in a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

On Linux or macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## 8. Reproduce the Pipeline

Start Jupyter from the repository root:

```bash
jupyter lab
```

Run the notebooks in this order:

1. `notebooks/1_Preprocessing.ipynb`
2. `notebooks/2_Data_Modeling_Validation.ipynb`
3. `notebooks/3_Model_Serving.ipynb`

The first notebook regenerates `artifacts/alert_correlation/normalized_alerts.csv`. This generated CSV is ignored by Git because it can be reproduced from the dataset. The second notebook regenerates the model and validation metrics; the committed JSON files provide a reference run. The third notebook demonstrates online-style scoring against recent alert history.

## 9. Python API

The shared implementation is in [`src/alert_correlation/core.py`](src/alert_correlation/core.py). Key functions include:

- `preprocess_ait_ads(...)` for normalization and phase-window attachment;
- `load_alerts(...)` for reading normalized alerts;
- `pair_features(...)` for extracting correlation indicators;
- `iter_candidate_pairs(...)` for bounded candidate generation;
- `select_history_candidates(...)` for diverse recent-history selection.

The module is dependency-free and can be imported directly from the repository source tree.

## 10. Limitations and Responsible Interpretation

- The project is a research and demonstration baseline, not a production SIEM correlation engine.
- Labels are weak phase-window labels rather than analyst-confirmed pair relationships.
- Only three AIT-ADS scenarios are used, with one scenario reserved for the final demonstration.
- The model assumes conditional independence between binary features given the pair class.
- The serving notebook uses an in-memory history and does not provide persistence, alert deduplication, or analyst feedback.
- Results should not be generalized to other environments without additional scenarios and independent ground truth.

## 11. Reference

Landauer, M., Skopik, F., and Wurzenberger, M. **AIT-ADS: A Dataset for Intrusion Detection and Alert Correlation**. [AIT-ADS on Zenodo](https://zenodo.org/records/8263181).

## 12. Project Documentation

- [Project workflow](docs/PROJECT_WORKFLOW.md)
- [Dataset documentation](data/AIT-ADS/README.md)
