# 📊 Uncloak Data & Benchmark Directory

This directory is reserved for training datasets, benchmark extracts, and feature matrices.

> [!WARNING] Anti-Leak & Repository Size Protection
> Never commit large raw PCAP files or multi-gigabyte CSVs to Git.
> Raw files in `data/raw/` and `*.csv` are automatically ignored by `.gitignore`.

---

## 📁 Recommended Structure

```text
data/
├── README.md               # This guide
├── raw/                    # (Ignored) Local download directory for CTU-13 raw PCAPs / CSVs
├── samples/                # Small test fixtures (< 100 rows) for unit tests
└── ctu13_features.csv      # Extracted feature matrix for Random Forest training
```

---

## 🔬 Expected Training Feature Schema

The training pipeline expects a CSV table with exactly these 8 columns:

| Column | Type | Description |
| :--- | :--- | :--- |
| `delta_t_mean` | `float` | Mean inter-burst pause time (seconds) |
| `delta_t_std` | `float` | Standard deviation of intervals |
| `delta_t_cv` | `float` | Coefficient of Variation (`std / mean`) |
| `burst_bytes_iqr` | `float` | Interquartile range of burst sizes in bytes |
| `payload_packet_ratio` | `float` | Ratio of non-pure-ACK packets |
| `out_in_ratio` | `float` | Ratio of bytes transmitted vs received |
| `sni_asn_mismatch` | `int` | `1` if SNI domain does not match destination ASN, else `0` |
| `label` | `int` | `0` = Benign enterprise traffic, `1` = Malicious C2 Beacon |

---

## 🔗 Official Benchmark Sources
- **CTU-13 Dataset :** [Stratosphere IPS Project](https://www.stratosphereips.org/datasets-ctu13)
- Scenarios recommended for training : Scenario 1 (Neris), Scenario 4 (Rbot), Scenario 9 (Virut), Scenario 10 (Rbot).
