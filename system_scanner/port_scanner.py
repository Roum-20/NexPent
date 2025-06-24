import socket
import streamlit as st

def scan_ports_with_progress(ip):
    open_ports = []
    total_ports = 65535
    progress = st.progress(0, text="Scanning ports...")
    
    for i, port in enumerate(range(1, total_ports + 1), 1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.05)  # Adjust for speed/accuracy
            result = s.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            s.close()
        except:
            continue

        # Update progress
        if i % 250 == 0 or i == total_ports:
            progress.progress(i / total_ports, text=f"Scanning port {port}...")

    progress.empty()  # Remove progress bar when done
    return open_ports
