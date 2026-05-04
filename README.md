# NexPent

NexPent is an advanced browser-based Vulnerability Assessment and Penetration Testing (VAPT) toolkit. It provides real-time security scanning capabilities, shifting from simulated testing to actual network-based analysis.

## Features

*   **Real-time Vulnerability Scanning:** Performs live testing for common web vulnerabilities (SQLi, XSS, etc.) using `fetch()`-based requests.
*   **Subdomain Enumeration:** Discovers subdomains associated with target domains by querying live APIs.
*   **CVE Lookup:** Integrates with real-world vulnerability databases (e.g., NVD) to retrieve the latest Common Vulnerabilities and Exposures.
*   **Port Scanning & Brute-Forcing:** Offers functional port scanning and simulated brute-forcing features to evaluate security posture.
*   **Browser-Based Architecture:** All the security assessments and reporting are handled securely within a modern browser interface, without the need for complex desktop installations.

## Tech Stack

*   **Frontend:** HTML5, CSS3, JavaScript (ES6)
*   **APIs:** Integrates with public APIs for threat intelligence and vulnerability data gathering.

## Getting Started

1.  Clone the repository:
    ```bash
    git clone https://github.com/Roum-20/NexPent.git
    ```
2.  Navigate to the project directory:
    ```bash
    cd NexPent
    ```
3.  Open `index.html` in your web browser. Or, to avoid CORS issues for some fetch requests, serve the directory via a local web server:
    ```bash
    npx serve .
    ```

## Disclaimer

This tool is strictly for educational purposes and authorized penetration testing only. Do not use NexPent to scan targets without explicit, written permission from the system owners. The developers assume no liability and are not responsible for any misuse or damage caused by this program.
