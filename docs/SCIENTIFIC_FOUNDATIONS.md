# Scientific Foundations & Literature Review: Uncloak

Uncloak bridges passive statistical network flow inspection, zero-decryption TLS fingerprinting (JA4+), live Win32 socket-to-process attribution, and surgical TCP teardown / per-application containment.

This document catalogs verified peer-reviewed publications and technical references grounding Uncloak's architecture. Every DOI and arXiv identifier below has been verified.

---

## Strategic Architecture Mapping

| Uncloak Architectural Subsystem | Supporting Research & Technical Grounding | Key Insight |
| :--- | :--- | :--- |
| **Pillar 1: Cadence & Burst Timing** | Yilmaz et al. (Springer IJIS 2026), Parssegny et al. (ARES 2025) | Timing-based flow metadata analysis isolates periodic beaconing without payload decryption, while requiring robust estimators against jitter. |
| **Pillar 2: Zero-Decryption TLS (JA4+, SNI)** | Matoušek et al. (IEEE CNSM 2024), Theofanous et al. (ACM WWW 2024), Shbair et al. (2020) | ClientHello metadata and JA4+ fingerprints provide high-value contributory signals, though malleable C2 profiles and shared TLS stacks (Schannel) prevent JA4+ from serving as a standalone verdict. |
| **Pillar 3: Host-Network Attribution** | Haas, Sommer & Fischer (IFIP SEC 2020), Liang et al. (IETF Draft 2026) | Combining network flow telemetry with host process tables bridges the network-only blindspot of NIDS/RITA. |
| **Pillar 4: Explainable ML Inference** | Yang et al. (Computer Networks 2024), Lo et al. (2022) | Lightweight tree ensembles and flow-metadata models outperform heavy black-box architectures on encrypted C2 traffic when evaluated on precision-recall and false-positive rate. |
| **Pillar 5: TCP Teardown & Containment Limits** | Vectra AI Technical Guidance, ExtraHop Technical Guidance | Out-of-band TCP RSTs sever active sessions immediately, but short-lived HTTP(S) beacons reconnect on the next sleep cycle unless paired with per-application firewall containment. |

---

## 1. Statistical Beaconing & Encrypted Flow Metadata

1. **Yilmaz, M. T., Doğan, F., Söğüt, E., Algül, E., & Aksoy, Ç. (2026) - *Beaconing detection via timing-based flow metadata analysis: implications for SCADA/ICS***
   * *Publication:* International Journal of Information Security, Springer, Vol. 25, Issue 5.
   * *Uncloak Role:* Validates timing-based metadata analysis on encrypted flows using inter-arrival dispersion.
   * *Ref:* [DOI: 10.1007/s10207-026-01335-w](https://doi.org/10.1007/s10207-026-01335-w)

2. **Parssegny, C., Mazel, J., Levillain, O., & Chifflier, P. (2025) - *Striking Back at Cobalt: Using Network Traffic Metadata to Detect Cobalt Strike Masquerading Command and Control Channels***
   * *Publication:* ARES 2025, LNCS 15992, Springer, pp. 163-185.
   * *Uncloak Role:* Demonstrates detection of masquerading Cobalt Strike C2 channels using network traffic metadata rather than payload inspection.
   * *Ref:* [arXiv:2506.08922](https://arxiv.org/abs/2506.08922)

3. **Daihes, Y., Tzaban, H., Nadler, A., & Shabtai, A. (2020) - *MORTON: Detection of Malicious Routines in Large-Scale DNS Traffic***
   * *Publication:* arXiv preprint.
   * *Uncloak Role:* Informs behavioral/routine detection in DNS query streams.
   * *Ref:* [arXiv:2008.02003](https://arxiv.org/abs/2008.02003)

---

## 2. Zero-Decryption TLS Fingerprinting

4. **Matoušek, P., Ryšavý, O., & Burgetová, I. (2024) - *Experience Report: Using JA4+ Fingerprints for Malware Detection in Encrypted Traffic***
   * *Publication:* 20th International Conference on Network and Service Management (IEEE CNSM 2024), Prague, pp. 1-5.
   * *Uncloak Role:* Establishes that JA4+ fingerprints overlap between malware and benign software sharing OS TLS stacks (e.g., Schannel) or uTLS, confirming JA4+ must be a contributory signal rather than a standalone verdict.
   * *Ref:* [DOI: 10.23919/CNSM62983.2024.10814358](https://doi.org/10.23919/CNSM62983.2024.10814358)

5. **Theofanous, M., et al. (2024) - *Fingerprinting the Shadows: Unmasking Malicious Servers with Machine Learning***
   * *Publication:* Companion Proceedings of the ACM Web Conference (WWW 2024).
   * *Uncloak Role:* Demonstrates passive TLS negotiation inspection for classifying malicious infrastructure without SSL interception.
   * *Ref:* [DOI: 10.1145/3589334.3645719](https://doi.org/10.1145/3589334.3645719)

6. **Shbair, W. M., Cholez, T., François, J., & Chrisment, I. (2020) - *Early Identification of Services in HTTPS Traffic***
   * *Publication:* arXiv preprint.
   * *Uncloak Role:* Grounding for early handshake inspection (SNI and initial TLS records) without full-stream decryption.
   * *Ref:* [arXiv:2008.08350](https://arxiv.org/abs/2008.08350)

---

## 3. Host-Network Correlation (Socket-to-PID Attribution)

7. **Haas, S., Sommer, R., & Fischer, M. (2020) - *zeek-osquery: Host-Network Correlation for Advanced Monitoring and Intrusion Detection***
   * *Publication:* IFIP SEC 2020.
   * *Uncloak Role:* Architectural precedent for pairing network flow monitoring with host process tables to eliminate network-only blindspots.
   * *Ref:* [arXiv:2002.04547](https://arxiv.org/abs/2002.04547)

8. **Liang, B., et al. (2026) - *TCP Provenance Identifier Option***
   * *Publication:* IETF Internet-Draft (`draft-liang-tcp-provenance-option`).
   * *Uncloak Role:* Reflects industry convergence toward binding socket telemetry directly to host process identifiers (PID).
   * *Ref:* [IETF Datatracker](https://datatracker.ietf.org/doc/draft-liang-tcp-provenance-option/)

---

## 4. Machine Learning & Encrypted C2 Classification

9. **Yang, X., Ruan, S., Yue, Y., & Sun, B. (2024) - *PETNet: Plaintext-aware Encrypted Traffic Detection Network for identifying Cobalt Strike HTTPS traffics***
   * *Publication:* Computer Networks, Elsevier.
   * *Uncloak Role:* Benchmarks encrypted Cobalt Strike HTTPS traffic classification using flow-level features.
   * *Ref:* [DOI: 10.1016/j.comnet.2023.110120](https://doi.org/10.1016/j.comnet.2023.110120)

10. **Lo, W. W., Kulatilleke, G. K., Sarhan, M., Layeghy, S., & Portmann, M. (2022) - *XG-BoT: An Explainable Deep Graph Neural Network for Botnet Detection and Forensics***
    * *Publication:* arXiv preprint.
    * *Uncloak Role:* Highlights the importance of explainable forensics in automated network detection pipelines.
    * *Ref:* [arXiv:2207.09088](https://arxiv.org/abs/2207.09088)

---

## 5. Surgical Eviction & Containment Trade-offs

11. **Vectra AI - *TCP reset does not stop modern attacks***
    * *Publication:* Vectra AI Technical Guidance.
    * *Uncloak Role:* Documents why out-of-band TCP RST alone is insufficient against beacons that open a fresh connection on every sleep cycle, motivating Uncloak's pairing of `SetTcpEntry` with per-application Windows Firewall containment.
    * *Ref:* [Vectra AI Docs](https://docs.vectra.ai/operations/analyst-guidance/tcp-reset-does-not-stop-modern-attacks)

12. **ExtraHop - *TCP resets and C2: Prevent Command and Control & DoS Attacks***
    * *Publication:* ExtraHop Technical Blog.
    * *Uncloak Role:* Evaluates operational strengths and limitations of TCP RST injection for active session disruption.
    * *Ref:* [ExtraHop Blog](https://www.extrahop.com/blog/tcp-resets-rst-prevent-command-and-control-dos-attacks/)
