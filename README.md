# eBPF & PyTorch Network Intrusion Detection System (NIDS)

A high-performance, real-time, unsupervised Network Intrusion Detection System (NIDS) combining **kernel-space eBPF (XDP)** packet monitoring with a **PyTorch Autoencoder** running in user-space. Designed for Linux environments, this project leverages zero-copy ring buffers for ultra-low latency telemetry collection and dynamic thresholding to detect network traffic anomalies.

---

## 🚀 Key Features

* **Kernel-Space Telemetry (eBPF XDP):** Bypasses the traditional network stack overhead using eXpress Data Path (XDP) bytecode to intercept packets directly at the network driver level.
* **Zero-Copy Ring Buffers:** Safely streams packet metadata (length, protocol type) from the Linux kernel to user-space with minimal performance overhead.
* **Unsupervised Deep Learning (PyTorch Autoencoder):** Employs an autoencoder neural network trained exclusively on normal baseline traffic to detect anomalies via reconstruction Mean Squared Error (MSE).
* **Dynamic Thresholding:** Automatically calculates and adapts anomaly detection thresholds based on baseline traffic variance during the warm-up phase.
* **Audit Logging:** Built-in structured logging that records all operational states, warm-up progress, and security warnings into `nids_alerts.log`.
* **Testing Tooling:** Includes a built-in testing script (`udp_spike.py`) to simulate sudden traffic bursts and verify intrusion detection capabilities.

---

## 🛠️ Tech Stack

* **Language:** Python 3, C (eBPF kernel code)
* **Libraries & Frameworks:** PyTorch (`torch`), BCC (`bcc` / BPF Compiler Collection)
* **Kernel Tech:** eBPF, XDP (eXpress Data Path), Linux Ring Buffers
* **Version Control:** Git

---

## 📁 Repository Structure

```text
├── nids_app.py        # Main user-space application (PyTorch model, aggregation, ring buffer handling, logging)
├── nids_kern.c        # Low-level eBPF XDP kernel program for packet monitoring
├── udp_spike.py       # Testing script to simulate malicious/anomalous UDP traffic spikes
├── requirements.txt   # Project dependencies
└── README.md          # Project documentation