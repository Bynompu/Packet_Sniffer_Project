# Embedded Linux-Based Portable Packet Sniffer


A self-contained, portable network packet sniffer built on a **Raspberry Pi 5** with a real-time, web-based visualization dashboard. This project was developed as a BSc dissertation at the University of Cape Town to address the lack of user-friendly, cost-effective, and portable analysis tools for small-scale network environments.

Unlike traditional tools like Wireshark, which require a laptop and have a steep learning curve, this device is an all-in-one hardware solution for "at-a-glance" network health monitoring, wireless analysis, and security event detection.


## Core Features

* **Real-Time Dashboard:** A web-based UI provides a live-updating view of network health, including:
    * Interface Throughput (Mbps)
    * Protocol Distribution (TCP, UDP, etc.)
    * Server CPU/Memory Usage
* **Deep Packet Inspection:** A live log of all captured packets that can be clicked to open a detailed modal showing a full protocol tree and raw hexdump.
* **Wireless Environment Analysis:** Uses monitor mode to passively discover:
    * Nearby Wi-Fi Networks (from 802.11 Beacon frames).
    * Client Devices (from 802.11 Probe Requests).
* **Security Event Detection:** Automatically identifies and logs common threats:
    * ARP Spoofing Attacks.
    * Wi-Fi Deauthentication/Disassociation Attacks.
* **Session & Historical Analysis:**
    * Save, load, and delete capture sessions from a persistent database.
    * View "Top Talkers" (by packets/data) and "Top Services" (by port).
    * Visualize device conversations as a dynamic network graph.
    * Review a "Global Stats" dashboard for analytics across *all* stored sessions.

##  Architecture & Tech Stack

A key challenge was integrating a *blocking* packet capture library (Scapy) with an *asynchronous* web server (FastAPI).

This was solved with a **decoupled, multi-process architecture**. A dedicated `Sniffer Process` captures packets and places them on a `multiprocessing.Queue`. The main `Backend Server Process` then reads from this queue, streams data to the UI via WebSockets, and writes to the database in a separate loop. This ensures the UI remains responsive and database writes never block live packet capture.

### Hardware
* **CPU:** Raspberry Pi 5
* **Display:** Waveshare 7-inch HDMI Touchscreen
* **Enclosure:** Custom Enclosure designed in Onshape

### Software
* **Operating System:** **Kali Linux** (chosen for its out-of-the-box monitor mode support on the RPi 5's onboard Wi-Fi).
* **Backend:**
    * **Framework:** FastAPI (for native `async`/`await` and WebSocket support).
    * **Packet Capture:** Scapy (used as a Python library for in-process capture).
    * **Concurrency:** Python **`multiprocessing`** library.
    * **Database:** PostgreSQL (chosen over SQLite for superior write concurrency).
* **Frontend:**
    * **Stack:** Vanilla JavaScript (ES6+), HTML5, and Tailwind CSS.
    * **Real-Time:** WebSockets (for low-latency, bidirectional communication).
    * **Visualization:** Chart.js (for dashboards) and Vis.js (for the network graph).

## 📊 Project Status & Limitations

This project successfully met all functional goals. The software is feature-complete, and the hardware is fully integrated.

However, the evaluation uncovered a **critical performance bottleneck**.

* **Performance Ceiling:** The system is perfectly stable on low-to-moderate traffic networks (e.g., home, small office, IoT testbeds).
* **Limitation:** It consistently becomes unstable and **shuts down when network traffic exceeds ~100 Mbps**. The 500 Mbps target was not met.
* **Cause:** This is believed to be a **hardware-level bottleneck** on the Raspberry Pi 5 platform (likely thermal or power-delivery related) when under heavy network I/O stress, *not* a simple software bug.

Despite this limitation, the device remains highly effective for its intended use case where traffic loads are typically well below 100 Mbps.

## Getting Started

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/Bynompu/PacketSnifferProject.git](https://github.com/Bynompu/PacketSnifferProject.git)
    cd PacketSnifferProject
    ```
2.  **Backend Setup (on the Raspberry Pi 5):**
    * Ensure `python3`, `pip`, and `postgresql` are installed.
    * Install Python dependencies:
        ```bash
        pip install -r requirements.txt 
        ```
    * Set up your PostgreSQL database (create user, password, and tables as defined in `scapy.server.py`).
    * Run the backend server:
        ```bash
        sudo python3 scapy.server.py
        ```
        *(Note: `sudo` is required for Scapy to access network interfaces).*

3.  **Frontend Access:**
    * Open the `capture_gui.html` file in a web browser (e.g., Chromium on the Pi's desktop). The JavaScript will automatically connect to the `ws://localhost:8765` WebSocket server.

## 🗺️ Future Work

Based on the project's findings, key priorities for future development include:

* **Investigate 100 Mbps Bottleneck:** Perform deep hardware profiling (thermals, power draw) and explore lower-level capture methods (e.g., C-based modules or eBPF).
* **GUI Enhancements:** Add controls to the web UI to enable monitor mode, removing the need for the command line.
* **Expand Security Rules:** Add detection for more network anomalies like port scans or DoS floods.

## Acknowledgements

* This project was submitted to the Department of Electrical Engineering at the University of Cape Town in partial fulfilment of the academic requirements for a Bachelor of Science degree in Electrical and Computer Engineering.
* Thank you to my supervisor, **Associate Professor Joyce Mwangama**, for her extensive and invaluable help.

