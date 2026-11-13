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

## Expected Training Feature Schema (v1 Contract)

The training and inference pipeline expects a CSV/Parquet table adhering to **Feature Schema v1** (computed over a sliding window of application bursts merged within 200 ms):

| Column | Type | Description |
| :--- | :--- | :--- |
| `n_bursts` | `int` | Number of logical bursts observed in the window |
| `iat_median` | `float` | Median inter-burst interval in seconds |
| `iat_mad_ratio` | `float` | Normalized Median Absolute Deviation (`MAD / median`) |
| `iat_iqr_ratio` | `float` | Normalized Interquartile Range (`IQR / median`) |
| `iat_bowley_skew` | `float` | Bowley skewness `(Q3 + Q1 - 2*Q2) / (Q3 - Q1)` |
| `size_out_median` | `float` | Median outbound burst size in bytes |
| `size_in_median` | `float` | Median inbound burst size in bytes |
| `size_mad_ratio` | `float` | Normalized MAD of burst sizes |
| `conn_per_burst` | `float` | Ratio of new TCP connections per burst (1.0 = ephemeral, ~0.0 = persistent) |
| `raw_ip_flag` | `int` | `1` if destination IP had no prior DNS/SNI resolution, else `0` |
| `proc_signed` | `int` | `1` if binary has valid Authenticode signature (`WinVerifyTrust`), else `0` |
| `proc_path_class` | `int` | `0` = System/Program Files, `1` = User-writable, `2` = Temp/AppData/Downloads |
| `label` | `int` | `0` = Benign enterprise traffic, `1` = Malicious C2 Beacon |

---

## Dataset Strategy
- **Primary Training & Evaluation (Modern Lab Corpus):** Multi-day benign Windows 10/11 enterprise traffic (Teams, Edge, OneDrive, Windows Update, Slack) combined with controlled C2 captures (Sliver, Havoc) across a grid of sleep intervals and jitter percentages.
- **Historical Context Only:** The **CTU-13 Dataset** ([Stratosphere IPS](https://www.stratosphereips.org/datasets-ctu13)) is cited for historical background only; its legacy 2011 BinetFlow format does not contain TLS SNI, process attribution, or burst-level timing structures required by Schema v1.
