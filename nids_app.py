#!/usr/bin/env python3
"""
eBPF & PyTorch Network Intrusion Detection System (NIDS)
Author: Govind Krishna Gopakumar
Description: Real-time unsupervised NIDS using kernel-space eBPF XDP packet monitoring,
             zero-copy ring buffers, time-window feature aggregation, and a PyTorch Autoencoder.
"""

import os
import sys
import time
import argparse
import logging
import torch
import torch.nn as nn
import torch.optim as optim
from bcc import BPF

# Configure File and Console Logging locally in the project directory
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("nids_alerts.log"),
        logging.StreamHandler(sys.stdout)
    ]
)


class NIDSAutoencoder(nn.Module):
    def __init__(self, input_dim=6):
        super(NIDSAutoencoder, self).__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 4),
            nn.ReLU(),
            nn.Linear(4, 2),
            nn.ReLU()
        )
        self.decoder = nn.Sequential(
            nn.Linear(2, 4),
            nn.ReLU(),
            nn.Linear(4, input_dim)
        )

    def forward(self, x):
        return self.decoder(self.encoder(x))


class TrafficWindowAggregator:
    def __init__(self, window_size_sec=2.0):
        self.window_size = window_size_sec
        self.current_window_start = time.time()
        self.packet_count = 0
        self.total_bytes = 0
        self.tcp_count = 0
        self.udp_count = 0
        self.icmp_count = 0

    def add_packet(self, pkt_len, protocol):
        now = time.time()
        if now - self.current_window_start >= self.window_size:
            vector = self.flush_window()
            self.current_window_start = now
            return vector

        self.packet_count += 1
        self.total_bytes += pkt_len
        if protocol == 6:
            self.tcp_count += 1
        elif protocol == 17:
            self.udp_count += 1
        elif protocol == 1:
            self.icmp_count += 1
        return None

    def flush_window(self):
        avg_len = self.total_bytes / max(1, self.packet_count)
        vector = [
            float(self.packet_count),
            float(self.total_bytes),
            float(avg_len),
            float(self.tcp_count),
            float(self.udp_count),
            float(self.icmp_count)
        ]
        self.packet_count = 0
        self.total_bytes = 0
        self.tcp_count = 0
        self.udp_count = 0
        self.icmp_count = 0
        return vector


def main():
    parser = argparse.ArgumentParser(description="eBPF & PyTorch Network Intrusion Detection System")
    parser.add_argument("--interface", type=str, default="lo", help="Network interface to monitor (default: lo)")
    parser.add_argument("--window", type=float, default=2.0, help="Time window size in seconds (default: 2.0)")
    parser.add_argument("--warmup", type=int, default=10, help="Number of baseline training windows (default: 10)")
    args = parser.parse_args()

    if os.geteuid() != 0:
        logging.error("This script requires root privileges to load eBPF bytecode. Please run with sudo.")
        sys.exit(1)

    kernel_file = "nids_kern.c"
    if not os.path.exists(kernel_file):
        logging.error(f"Kernel program file '{kernel_file}' not found in current directory.")
        sys.exit(1)

    with open(kernel_file, "r") as f:
        bpf_source = f.read()

    logging.info(f"Compiling and loading eBPF XDP program on interface '{args.interface}'...")
    try:
        b = BPF(text=bpf_source)
        fn = b.load_func("monitor_packets", BPF.XDP)
        b.attach_xdp(args.interface, fn, 0)
    except Exception as e:
        logging.error(f"Failed to attach XDP program: {e}")
        sys.exit(1)

    model = NIDSAutoencoder(input_dim=6)
    criterion = nn.MSELoss(reduction='none')
    optimizer = optim.Adam(model.parameters(), lr=0.01)

    is_training = True
    train_buffer = []
    anomaly_threshold = 1.0
    aggregator = TrafficWindowAggregator(window_size_sec=args.window)

    logging.info(f"[*] WARM-UP PHASE: Collecting {args.warmup} baseline traffic windows...")

    def handle_event(cpu, data, size):
        nonlocal is_training, train_buffer, anomaly_threshold
        event = b["events"].event(data)
        feature_vector = aggregator.add_packet(event.pkt_len, event.protocol)

        if feature_vector:
            if is_training:
                train_buffer.append(feature_vector)
                logging.info(
                    f"[Warm-up] Collected {len(train_buffer)}/{args.warmup} windows | Metrics: {feature_vector}")
                if len(train_buffer) >= args.warmup:
                    logging.info("Training PyTorch Autoencoder on baseline traffic...")
                    model.train()
                    dataset = torch.tensor(train_buffer, dtype=torch.float32)
                    for epoch in range(50):
                        optimizer.zero_grad()
                        output = model(dataset)
                        loss = criterion(output, dataset).mean()
                        loss.backward()
                        optimizer.step()

                    model.eval()
                    with torch.no_grad():
                        reconstructed = model(dataset)
                        losses = criterion(reconstructed, dataset).mean(dim=1)
                        anomaly_threshold = max(losses.max().item() * 2.5, 0.5)

                    is_training = False
                    logging.info(f"[+] Training complete! Dynamic Anomaly Threshold set to: {anomaly_threshold:.4f}")
                    logging.info("[*] Switching to Live Anomaly Detection Mode...")
            else:
                input_tensor = torch.tensor([feature_vector], dtype=torch.float32)
                with torch.no_grad():
                    reconstructed = model(input_tensor)
                    loss = criterion(reconstructed, input_tensor).mean().item()

                if loss > anomaly_threshold:
                    logging.warning(
                        f"[!] ANOMALY DETECTED! MSE Loss: {loss:.4f} (Threshold: {anomaly_threshold:.4f}) | Metrics: {feature_vector}")
                else:
                    logging.info(f"[*] Normal Traffic. MSE Loss: {loss:.4f} | Metrics: {feature_vector}")

    b["events"].open_ring_buffer(handle_event)

    try:
        while True:
            b.ring_buffer_poll(timeout=100)
    except KeyboardInterrupt:
        logging.info("\n[*] Detaching XDP program and exiting...")
        b.remove_xdp(args.interface, 0)


if __name__ == "__main__":
    main()
