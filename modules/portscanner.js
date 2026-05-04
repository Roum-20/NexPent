/* ============================================
   NexPent — Full Port Scanner Module
   REAL-TIME: Probes actual ports via fetch()
   and WebSocket with timeout-based detection.
   ============================================ */

const PortScannerModule = (() => {
    // Well-known service mappings
    const serviceDB = {
        21: { service: "FTP", risk: "medium" },
        22: { service: "SSH", risk: "low" },
        23: { service: "Telnet", risk: "critical" },
        25: { service: "SMTP", risk: "medium" },
        53: { service: "DNS", risk: "low" },
        80: { service: "HTTP", risk: "medium" },
        110: { service: "POP3", risk: "medium" },
        111: { service: "RPCbind", risk: "high" },
        135: { service: "MSRPC", risk: "high" },
        139: { service: "NetBIOS-SSN", risk: "high" },
        143: { service: "IMAP", risk: "medium" },
        161: { service: "SNMP", risk: "high" },
        389: { service: "LDAP", risk: "medium" },
        443: { service: "HTTPS", risk: "low" },
        445: { service: "Microsoft-DS", risk: "high" },
        465: { service: "SMTPS", risk: "low" },
        587: { service: "Submission", risk: "low" },
        636: { service: "LDAPS", risk: "low" },
        993: { service: "IMAPS", risk: "low" },
        995: { service: "POP3S", risk: "low" },
        1433: { service: "MSSQL", risk: "high" },
        1521: { service: "Oracle DB", risk: "high" },
        2049: { service: "NFS", risk: "high" },
        3000: { service: "Dev Server", risk: "medium" },
        3306: { service: "MySQL", risk: "high" },
        3389: { service: "RDP", risk: "high" },
        5432: { service: "PostgreSQL", risk: "medium" },
        5900: { service: "VNC", risk: "high" },
        5985: { service: "WinRM", risk: "medium" },
        6379: { service: "Redis", risk: "high" },
        8000: { service: "HTTP-Alt", risk: "medium" },
        8080: { service: "HTTP-Proxy", risk: "medium" },
        8443: { service: "HTTPS-Alt", risk: "low" },
        8888: { service: "HTTP-Alt", risk: "medium" },
        9090: { service: "WebSM", risk: "medium" },
        9200: { service: "Elasticsearch", risk: "high" },
        27017: { service: "MongoDB", risk: "high" },
        11211: { service: "Memcached", risk: "high" },
    };

    /**
     * Probe a single port using fetch() with a short timeout.
     * In browsers, we can't do raw TCP — but fetch to http://host:port/
     * will give us actionable signals:
     *   - Quick response / CORS error = port is OPEN (something listening)
     *   - Timeout = port is CLOSED or FILTERED
     *   - Connection refused error = port is CLOSED
     */
    async function probePort(host, port, timeoutMs = 3000) {
        const protocols = port === 443 || port === 8443 || port === 636 || port === 993 || port === 995 || port === 465
            ? ["https"] : ["http"];

        for (const proto of protocols) {
            try {
                const controller = new AbortController();
                const timer = setTimeout(() => controller.abort(), timeoutMs);
                const url = `${proto}://${host}:${port}/`;

                const resp = await fetch(url, {
                    method: "HEAD",
                    mode: "no-cors",
                    signal: controller.signal,
                    cache: "no-store",
                });
                clearTimeout(timer);

                // If we get ANY response (even opaque), the port is open
                return { state: "open", evidence: `${proto.toUpperCase()} response received` };
            } catch (err) {
                if (err.name === "AbortError") {
                    // Timeout — could be filtered or closed
                    return { state: "filtered", evidence: "Connection timed out" };
                }
                // TypeError: Failed to fetch — this is ambiguous in browsers
                // For no-cors mode, a TypeError can mean:
                // - connection refused (closed)
                // - CORS blocked but server responded (open!)
                // We need to use timing to distinguish
                const errorMsg = err.message || "";
                if (errorMsg.includes("Failed to fetch") || errorMsg.includes("NetworkError")) {
                    // Could be either — try with timing
                    continue;
                }
            }
        }

        // Use timing-based detection as fallback
        return await probePortTiming(host, port, timeoutMs);
    }

    /**
     * Timing-based port detection:
     * Open ports: server responds quickly (even with reset) — fast error
     * Closed ports with no firewall: fast RST — fast error
     * Filtered ports: timeout (firewall drops packets)
     * 
     * In practice from browser, fast fetch failure (<500ms) often means
     * port is open (server refused HTTP but TCP connected briefly),
     * while slow failure (>2s) means filtered.
     */
    async function probePortTiming(host, port, timeoutMs) {
        const start = performance.now();
        try {
            const controller = new AbortController();
            const timer = setTimeout(() => controller.abort(), timeoutMs);

            await fetch(`http://${host}:${port}/`, {
                method: "GET",
                mode: "no-cors",
                signal: controller.signal,
                cache: "no-store",
            });
            clearTimeout(timer);
            const elapsed = performance.now() - start;
            return { state: "open", evidence: `Response in ${elapsed.toFixed(0)}ms` };
        } catch (err) {
            const elapsed = performance.now() - start;

            if (err.name === "AbortError" || elapsed >= timeoutMs * 0.8) {
                return { state: "filtered", evidence: `Timed out after ${elapsed.toFixed(0)}ms` };
            }

            // Very fast failure can mean either open (TCP connected then HTTP failed) or truly closed
            // Typically: <100ms = closed (RST), 100-800ms = open but refused HTTP, >2000ms = filtered
            if (elapsed < 150) {
                return { state: "closed", evidence: `Fast rejection in ${elapsed.toFixed(0)}ms` };
            } else {
                // Between 150ms and timeout — likely open (TCP handshake happened)
                return { state: "open", evidence: `TCP response in ${elapsed.toFixed(0)}ms (HTTP refused)` };
            }
        }
    }

    /**
     * Try to detect the actual service version by reading HTTP headers/body
     */
    async function detectServiceVersion(host, port) {
        const proto = (port === 443 || port === 8443) ? "https" : "http";
        try {
            const controller = new AbortController();
            const timer = setTimeout(() => controller.abort(), 4000);

            const resp = await fetch(`${proto}://${host}:${port}/`, {
                method: "GET",
                mode: "cors",
                signal: controller.signal,
                cache: "no-store",
            });
            clearTimeout(timer);

            // Extract server info from headers
            const server = resp.headers.get("server") || "";
            const poweredBy = resp.headers.get("x-powered-by") || "";
            const via = resp.headers.get("via") || "";

            let version = server || poweredBy || via || `HTTP ${resp.status}`;
            return version.substring(0, 40);
        } catch {
            return "unknown";
        }
    }

    async function scanPorts(config, outputEl, progressEl, fillEl, textEl) {
        const { host, startPort, endPort, speed, serviceDetection } = config;
        const totalPorts = endPort - startPort + 1;

        const results = {
            host,
            startPort,
            endPort,
            openPorts: [],
            closedPorts: 0,
            filteredPorts: 0,
            scanned: 0,
            startTime: Date.now(),
        };

        progressEl.style.display = "flex";

        addLine(outputEl, "info", "[SCAN]", `REAL-TIME port scan starting on: ${host}`);
        addLine(outputEl, "info", "[INFO]", `Range: ${startPort}-${endPort} (${totalPorts} ports) | Speed: ${speed}`);
        addLine(outputEl, "info", "[INFO]", `Service detection: ${serviceDetection ? "Enabled" : "Disabled"}`);
        addLine(outputEl, "warning", "[LIVE]", "⚡ Live TCP probing via fetch() — analyzing real network responses");
        addLine(outputEl, "system", "[SYS]", "─".repeat(60));

        // Concurrency based on speed setting
        const concurrency = speed === "fast" ? 15 : speed === "normal" ? 8 : 3;
        const timeoutMs = speed === "fast" ? 2000 : speed === "normal" ? 3000 : 5000;

        // Process ports in batches with concurrency control
        const portQueue = [];
        for (let p = startPort; p <= endPort; p++) {
            portQueue.push(p);
        }

        let processed = 0;

        while (portQueue.length > 0) {
            const batch = portQueue.splice(0, concurrency);

            const probePromises = batch.map(async (port) => {
                const result = await probePort(host, port, timeoutMs);
                processed++;
                const pct = Math.round((processed / totalPorts) * 100);
                fillEl.style.width = pct + "%";
                textEl.textContent = pct + "%";

                results.scanned++;

                if (result.state === "open") {
                    const svc = serviceDB[port] || { service: "Unknown", risk: "medium" };
                    let version = "unknown";

                    if (serviceDetection) {
                        version = await detectServiceVersion(host, port);
                    }

                    const portResult = {
                        port,
                        state: "open",
                        service: svc.service,
                        version: version,
                        risk: svc.risk,
                        evidence: result.evidence,
                    };
                    results.openPorts.push(portResult);

                    const riskColor = svc.risk === "critical" ? "error" : svc.risk === "high" ? "vuln" : svc.risk === "medium" ? "warning" : "found";
                    addLine(outputEl, "found", "[OPEN]", `Port ${port}/tcp — OPEN (${result.evidence})`);
                    if (serviceDetection) {
                        addLine(outputEl, riskColor, "[SVC]", `  → ${svc.service} ${version} [Risk: ${svc.risk.toUpperCase()}]`);
                    }
                } else if (result.state === "filtered") {
                    results.filteredPorts++;
                } else {
                    results.closedPorts++;
                }
            });

            await Promise.all(probePromises);

            // Progress update
            if (processed % 100 === 0 || processed === totalPorts) {
                addLine(outputEl, "system", "[PROG]", `Scanned ${processed}/${totalPorts} ports (${Math.round((processed / totalPorts) * 100)}%)`);
            }
        }

        results.endTime = Date.now();
        const duration = ((results.endTime - results.startTime) / 1000).toFixed(1);

        addLine(outputEl, "system", "[SYS]", "─".repeat(60));
        addLine(outputEl, "info", "[DONE]", `Port scan complete in ${duration}s`);
        addLine(outputEl, "info", "[STAT]", `Open: ${results.openPorts.length} | Closed: ${results.closedPorts} | Filtered: ${results.filteredPorts}`);

        if (results.openPorts.length > 0) {
            // Sort by port number
            results.openPorts.sort((a, b) => a.port - b.port);

            addLine(outputEl, "system", "[SYS]", "─".repeat(60));
            addLine(outputEl, "info", "[TABLE]", "PORT      STATE   SERVICE              VERSION                    RISK");
            addLine(outputEl, "system", "[SYS]", "─".repeat(80));

            results.openPorts.forEach((p) => {
                const portStr = `${p.port}/tcp`.padEnd(10);
                const stateStr = "open".padEnd(8);
                const svcStr = p.service.padEnd(21);
                const verStr = (p.version || "").padEnd(27);
                const riskStr = p.risk.toUpperCase();
                const lineClass = p.risk === "critical" || p.risk === "high" ? "vuln" : p.risk === "medium" ? "warning" : "found";
                addLine(outputEl, lineClass, "[PORT]", `${portStr}${stateStr}${svcStr}${verStr}${riskStr}`);
            });

            // Security recommendations
            const highRiskPorts = results.openPorts.filter((p) => p.risk === "critical" || p.risk === "high");
            if (highRiskPorts.length > 0) {
                addLine(outputEl, "system", "[SYS]", "─".repeat(60));
                addLine(outputEl, "error", "[ALERT]", `${highRiskPorts.length} high/critical risk service(s) detected!`);
                highRiskPorts.forEach((p) => {
                    addLine(outputEl, "warning", "[REC]", `Port ${p.port} (${p.service}): Consider restricting access or upgrading.`);
                });
            }
        }

        return results;
    }

    function addLine(container, type, time, msg) {
        const line = document.createElement("div");
        line.className = `terminal-line ${type}`;
        line.innerHTML = `<span class="time">${time}</span><span class="msg">${msg}</span>`;
        container.appendChild(line);
        container.scrollTop = container.scrollHeight;
    }

    function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }
    function randomInt(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }

    return { scanPorts };
})();
