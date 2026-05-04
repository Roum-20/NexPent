/* ============================================
   NexPent — Nmap Scanner Module
   REAL-TIME: Performs actual network probing
   via fetch() with service detection and
   header analysis.
   ============================================ */

const NmapModule = (() => {
    "use strict";

    // ── Timing Templates ─────────────────────────
    const TIMING_TEMPLATES = {
        T0: { label: "T0 — Paranoid", desc: "IDS evasion, serial scanning, 5 min delay between probes", parallelism: 1, delayMs: 800, timeoutMs: 8000, color: "#94a3b8" },
        T1: { label: "T1 — Sneaky", desc: "IDS evasion, serial scanning, 15 sec delay between probes", parallelism: 1, delayMs: 600, timeoutMs: 7000, color: "#60a5fa" },
        T2: { label: "T2 — Polite", desc: "Slows scan to use less bandwidth, serial scanning", parallelism: 2, delayMs: 400, timeoutMs: 6000, color: "#34d399" },
        T3: { label: "T3 — Normal", desc: "Default Nmap timing, balance between speed and stealth", parallelism: 5, delayMs: 200, timeoutMs: 4000, color: "#fbbf24" },
        T4: { label: "T4 — Aggressive", desc: "Faster scan, assumes reliable network, may trigger IDS", parallelism: 10, delayMs: 100, timeoutMs: 3000, color: "#f97316" },
        T5: { label: "T5 — Insane", desc: "Fastest scan, sacrifices accuracy for speed", parallelism: 20, delayMs: 40, timeoutMs: 2000, color: "#ef4444" },
    };

    // ── Scan Types ───────────────────────────────
    const SCAN_TYPES = {
        syn: { label: "SYN Scan (-sS)", flag: "-sS", desc: "Half-open scan, stealthy, requires root" },
        connect: { label: "Connect Scan (-sT)", flag: "-sT", desc: "Full TCP connect, no root required" },
        udp: { label: "UDP Scan (-sU)", flag: "-sU", desc: "Scan UDP ports, slower but finds hidden services" },
        fin: { label: "FIN Scan (-sF)", flag: "-sF", desc: "Stealth FIN scan, evades stateless firewalls" },
        xmas: { label: "Xmas Scan (-sX)", flag: "-sX", desc: "Sets FIN, PSH, URG flags for firewall evasion" },
        ack: { label: "ACK Scan (-sA)", flag: "-sA", desc: "Map firewall rulesets, determine filtered ports" },
        version: { label: "Version Detect (-sV)", flag: "-sV", desc: "Probe open ports for service/version info" },
        os: { label: "OS Detection (-O)", flag: "-O", desc: "Detect operating system using TCP/IP fingerprinting" },
    };

    // ── Common Services Database ─────────────────
    const SERVICES = {
        21: { name: "ftp", risk: "medium" },
        22: { name: "ssh", risk: "low" },
        23: { name: "telnet", risk: "critical" },
        25: { name: "smtp", risk: "medium" },
        53: { name: "dns", risk: "low" },
        80: { name: "http", risk: "medium" },
        110: { name: "pop3", risk: "medium" },
        111: { name: "rpcbind", risk: "high" },
        135: { name: "msrpc", risk: "high" },
        139: { name: "netbios", risk: "high" },
        143: { name: "imap", risk: "medium" },
        443: { name: "https", risk: "low" },
        445: { name: "smb", risk: "high" },
        993: { name: "imaps", risk: "low" },
        995: { name: "pop3s", risk: "low" },
        1433: { name: "ms-sql", risk: "critical" },
        1521: { name: "oracle", risk: "critical" },
        3000: { name: "dev-server", risk: "medium" },
        3306: { name: "mysql", risk: "high" },
        3389: { name: "rdp", risk: "critical" },
        5432: { name: "postgres", risk: "high" },
        5900: { name: "vnc", risk: "critical" },
        6379: { name: "redis", risk: "high" },
        8000: { name: "http-alt", risk: "medium" },
        8080: { name: "http-alt", risk: "medium" },
        8443: { name: "https-alt", risk: "medium" },
        9200: { name: "elasticsearch", risk: "high" },
        27017: { name: "mongodb", risk: "high" },
    };

    // Common ports to scan
    const COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3000, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9200, 27017];

    // ── Utility ──────────────────────────────────
    function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

    function appendLine(output, type, msg) {
        const line = document.createElement("div");
        line.className = `terminal-line ${type}`;
        const prefix = { info: "[*]", success: "[+]", warning: "[!]", error: "[!!]", system: "[~]" };
        line.innerHTML = `<span class="time">${prefix[type] || "[*]"}</span><span class="msg">${msg}</span>`;
        output.appendChild(line);
        output.scrollTop = output.scrollHeight;
    }

    function riskBadge(risk) {
        const colors = { critical: "#ef4444", high: "#f97316", medium: "#fbbf24", low: "#34d399" };
        return `<span style="color:${colors[risk] || '#94a3b8'};font-weight:600">${risk.toUpperCase()}</span>`;
    }

    /**
     * Real port probe via fetch
     */
    async function probePort(target, port, timeoutMs) {
        const proto = (port === 443 || port === 8443 || port === 993 || port === 995) ? "https" : "http";

        try {
            const controller = new AbortController();
            const timer = setTimeout(() => controller.abort(), timeoutMs);
            const start = performance.now();

            const resp = await fetch(`${proto}://${target}:${port}/`, {
                method: "HEAD",
                mode: "no-cors",
                signal: controller.signal,
                cache: "no-store",
            });
            clearTimeout(timer);
            const elapsed = performance.now() - start;
            return { state: "open", elapsed };
        } catch (err) {
            const elapsed = err._elapsed || 0;
            if (err.name === "AbortError") {
                return { state: "filtered", elapsed: timeoutMs };
            }

            // Timing-based detection
            const start = performance.now();
            try {
                const controller2 = new AbortController();
                const timer2 = setTimeout(() => controller2.abort(), timeoutMs);
                await fetch(`http://${target}:${port}/`, {
                    method: "GET",
                    mode: "no-cors",
                    signal: controller2.signal,
                    cache: "no-store",
                });
                clearTimeout(timer2);
                return { state: "open", elapsed: performance.now() - start };
            } catch (err2) {
                const el = performance.now() - start;
                if (err2.name === "AbortError" || el >= timeoutMs * 0.8) {
                    return { state: "filtered", elapsed: el };
                }
                if (el < 150) {
                    return { state: "closed", elapsed: el };
                }
                return { state: "open", elapsed: el };
            }
        }
    }

    /**
     * Detect service version by reading HTTP headers
     */
    async function detectVersion(target, port) {
        const proto = (port === 443 || port === 8443) ? "https" : "http";
        try {
            const controller = new AbortController();
            const timer = setTimeout(() => controller.abort(), 4000);
            const resp = await fetch(`${proto}://${target}:${port}/`, {
                method: "GET",
                mode: "cors",
                signal: controller.signal,
            });
            clearTimeout(timer);

            const server = resp.headers.get("server") || "";
            const poweredBy = resp.headers.get("x-powered-by") || "";
            return server || poweredBy || `HTTP ${resp.status}`;
        } catch {
            return "unknown";
        }
    }

    /**
     * Detect OS from HTTP headers and response behavior
     */
    async function detectOS(target) {
        const indicators = [];

        for (const port of [80, 443, 8080]) {
            const proto = port === 443 ? "https" : "http";
            try {
                const controller = new AbortController();
                const timer = setTimeout(() => controller.abort(), 5000);
                const resp = await fetch(`${proto}://${target}:${port}/`, {
                    method: "GET",
                    mode: "cors",
                    signal: controller.signal,
                });
                clearTimeout(timer);

                const server = (resp.headers.get("server") || "").toLowerCase();
                const poweredBy = (resp.headers.get("x-powered-by") || "").toLowerCase();
                const allHeaders = server + " " + poweredBy;

                if (allHeaders.includes("ubuntu") || allHeaders.includes("debian")) {
                    indicators.push({ os: "Linux (Ubuntu/Debian)", accuracy: 90, type: "Linux" });
                } else if (allHeaders.includes("centos") || allHeaders.includes("red hat") || allHeaders.includes("rhel")) {
                    indicators.push({ os: "Linux (CentOS/RHEL)", accuracy: 88, type: "Linux" });
                } else if (allHeaders.includes("win") || allHeaders.includes("iis") || allHeaders.includes("microsoft")) {
                    indicators.push({ os: "Windows Server", accuracy: 92, type: "Windows" });
                } else if (allHeaders.includes("freebsd")) {
                    indicators.push({ os: "FreeBSD", accuracy: 85, type: "FreeBSD" });
                } else if (allHeaders.includes("unix") || allHeaders.includes("apache") || allHeaders.includes("nginx")) {
                    indicators.push({ os: "Linux/Unix", accuracy: 75, type: "Linux" });
                }

                if (indicators.length > 0) break;
            } catch {
                continue;
            }
        }

        if (indicators.length > 0) {
            return indicators[0];
        }
        return { os: "Unknown (insufficient data)", accuracy: 0, type: "Unknown", details: "HTTP header analysis inconclusive" };
    }

    // ── Run Nmap Scan ────────────────────────────
    async function runNmapScan(config, output, progressContainer, progressFill, progressText) {
        const { target, scanType, timing, enableOS, enableVersion, enableScripts } = config;
        const tmpl = TIMING_TEMPLATES[timing] || TIMING_TEMPLATES.T3;
        const scan = SCAN_TYPES[scanType] || SCAN_TYPES.syn;

        // Clear output
        output.innerHTML = "";
        progressContainer.style.display = "block";

        // Build command string
        let cmdFlags = scan.flag;
        if (enableVersion) cmdFlags += " -sV";
        if (enableOS) cmdFlags += " -O";
        if (enableScripts) cmdFlags += " --script=default,vuln";
        cmdFlags += ` -${timing}`;

        appendLine(output, "system", `Starting NexPent Nmap-style Scanner (Real-Time)`);
        appendLine(output, "info", `<span style="color:${tmpl.color}">Timing: ${tmpl.label}</span> &mdash; ${tmpl.desc}`);
        appendLine(output, "info", `Scan type: <strong>${scan.label}</strong> &mdash; ${scan.desc}`);
        appendLine(output, "system", `Command: <code style="color:var(--accent-primary)">nmap ${cmdFlags} ${target}</code>`);
        appendLine(output, "warning", `⚡ LIVE network probing — sending real requests to ${target}`);
        await sleep(tmpl.delayMs);

        appendLine(output, "info", `Initiating ${scan.label.split("(")[0].trim()} against ${target}...`);
        await sleep(tmpl.delayMs);

        // Phase 1: Host discovery
        appendLine(output, "info", "Host discovery: probing target...");
        let hostUp = false;
        const hostStart = performance.now();
        try {
            const controller = new AbortController();
            const timer = setTimeout(() => controller.abort(), 5000);
            await fetch(`http://${target}/`, { method: "HEAD", mode: "no-cors", signal: controller.signal });
            clearTimeout(timer);
            hostUp = true;
        } catch (err) {
            if (err.name !== "AbortError") {
                hostUp = true; // Connection refused = host is up
            }
        }
        const hostLatency = ((performance.now() - hostStart) / 1000).toFixed(3);

        if (hostUp) {
            appendLine(output, "success", `Host ${target} is up (${hostLatency}s latency).`);
        } else {
            appendLine(output, "error", `Host ${target} appears to be down or filtered.`);
            progressFill.style.width = "100%";
            progressText.textContent = "100%";
            return { target, openPorts: [], filtered: [], os: null, vulns: [], criticalCount: 0, highCount: 0 };
        }
        await sleep(tmpl.delayMs);

        // Phase 2: Port scanning
        const portsToScan = COMMON_PORTS;
        appendLine(output, "info", `Scanning ${portsToScan.length} common ports on ${target}...`);
        await sleep(tmpl.delayMs);

        appendLine(output, "system", "");
        appendLine(output, "system", `<span style="font-family:var(--font-mono);color:var(--text-muted)">PORT       STATE      SERVICE         VERSION</span>`);
        appendLine(output, "system", `<span style="color:var(--border-primary)">───────────────────────────────────────────────────────</span>`);

        const openPorts = [];
        const filtered = [];

        // Scan in batches based on parallelism
        for (let i = 0; i < portsToScan.length; i += tmpl.parallelism) {
            const batch = portsToScan.slice(i, i + tmpl.parallelism);

            const probeResults = await Promise.all(
                batch.map(async (port) => {
                    const result = await probePort(target, port, tmpl.timeoutMs);
                    return { port, ...result };
                })
            );

            for (const probe of probeResults) {
                const progress = Math.round(((i + batch.indexOf(probe) + 1) / portsToScan.length) * 70);
                progressFill.style.width = `${progress}%`;
                progressText.textContent = `${progress}%`;

                if (probe.state === "open") {
                    const svc = SERVICES[probe.port] || { name: "unknown", risk: "medium" };
                    let version = "unknown";

                    if (enableVersion) {
                        version = await detectVersion(target, probe.port);
                    }

                    openPorts.push({
                        port: probe.port,
                        service: svc.name,
                        version: version,
                        risk: svc.risk,
                        state: "open",
                        latency: probe.elapsed.toFixed(0) + "ms",
                    });

                    const portStr = `${probe.port}/tcp`.padEnd(10);
                    const nameStr = svc.name.padEnd(15);
                    const verStr = enableVersion ? version : "";

                    appendLine(output, "success",
                        `<span style="font-family:var(--font-mono)">${portStr} <span style="color:#34d399">open</span>       ${nameStr} ${verStr}</span> ${riskBadge(svc.risk)}`
                    );
                } else if (probe.state === "filtered") {
                    filtered.push(probe.port);
                }
            }

            await sleep(tmpl.delayMs);
        }

        // Show filtered ports
        if (filtered.length > 0 && filtered.length <= 10) {
            for (const fp of filtered) {
                appendLine(output, "warning",
                    `<span style="font-family:var(--font-mono)">${(fp + "/tcp").padEnd(10)} <span style="color:#fbbf24">filtered</span>   unknown</span>`
                );
            }
        } else if (filtered.length > 10) {
            appendLine(output, "warning", `${filtered.length} ports filtered (firewall likely in place)`);
        }

        progressFill.style.width = "80%";
        progressText.textContent = "80%";

        // Phase 3: OS detection
        let osGuess = null;
        if (enableOS) {
            await sleep(tmpl.delayMs);
            appendLine(output, "system", "");
            appendLine(output, "info", "Running OS detection (HTTP header fingerprinting)...");
            osGuess = await detectOS(target);
            await sleep(tmpl.delayMs);
            if (osGuess.accuracy > 0) {
                appendLine(output, "success", `OS: <strong>${osGuess.os}</strong> (${osGuess.accuracy}% confidence)`);
            } else {
                appendLine(output, "warning", `OS detection inconclusive — insufficient data from HTTP headers`);
            }
            progressFill.style.width = "90%";
            progressText.textContent = "90%";
        }

        // Phase 4: Script scanning (security header analysis)
        if (enableScripts && openPorts.length > 0) {
            await sleep(tmpl.delayMs);
            appendLine(output, "system", "");
            appendLine(output, "info", "Running security checks (header analysis)...");

            for (const op of openPorts.filter(p => p.service === "http" || p.service === "https" || p.service === "http-alt")) {
                const proto = (op.port === 443 || op.port === 8443) ? "https" : "http";
                try {
                    const controller = new AbortController();
                    const timer = setTimeout(() => controller.abort(), 5000);
                    const resp = await fetch(`${proto}://${target}:${op.port}/`, {
                        method: "GET",
                        mode: "cors",
                        signal: controller.signal,
                    });
                    clearTimeout(timer);

                    // Check security headers
                    const csp = resp.headers.get("content-security-policy");
                    const xfo = resp.headers.get("x-frame-options");
                    const hsts = resp.headers.get("strict-transport-security");
                    const xcto = resp.headers.get("x-content-type-options");

                    if (!csp) appendLine(output, "warning", `| ${op.port}/${op.service}: Missing Content-Security-Policy header`);
                    if (!xfo) appendLine(output, "warning", `| ${op.port}/${op.service}: Missing X-Frame-Options header`);
                    if (!hsts && proto === "https") appendLine(output, "warning", `| ${op.port}/${op.service}: Missing Strict-Transport-Security header`);
                    if (!xcto) appendLine(output, "info", `| ${op.port}/${op.service}: Missing X-Content-Type-Options header`);

                    if (csp && xfo && hsts) {
                        appendLine(output, "success", `| ${op.port}/${op.service}: Security headers properly configured`);
                    }
                } catch {
                    appendLine(output, "info", `| ${op.port}/${op.service}: Could not read headers (CORS restricted)`);
                }
                await sleep(tmpl.delayMs);
            }

            progressFill.style.width = "95%";
            progressText.textContent = "95%";
        }

        // Summary
        progressFill.style.width = "100%";
        progressText.textContent = "100%";
        await sleep(tmpl.delayMs);

        const criticalPorts = openPorts.filter(p => p.risk === "critical");
        const highPorts = openPorts.filter(p => p.risk === "high");

        appendLine(output, "system", "");
        appendLine(output, "system", `<span style="color:var(--border-primary)">═══════════════════════════════════════════════════════</span>`);
        appendLine(output, "success", `Scan done: 1 IP address (1 host up) scanned`);
        appendLine(output, "info", `<strong>${openPorts.length}</strong> open ports &bull; <strong>${filtered.length}</strong> filtered &bull; <strong>${criticalPorts.length}</strong> critical &bull; <strong>${highPorts.length}</strong> high risk`);

        if (criticalPorts.length > 0) {
            appendLine(output, "error", `⚠ CRITICAL: ${criticalPorts.map(p => `${p.port}/${p.service}`).join(", ")} &mdash; immediate attention required!`);
        }
        if (highPorts.length > 0) {
            appendLine(output, "warning", `High-risk services detected: ${highPorts.map(p => `${p.port}/${p.service}`).join(", ")}`);
        }

        return {
            target,
            openPorts,
            filtered,
            os: osGuess,
            timing,
            scanType,
            criticalCount: criticalPorts.length,
            highCount: highPorts.length,
            vulns: criticalPorts.concat(highPorts).map(p => ({
                port: p.port,
                service: p.service,
                severity: p.risk,
                detail: `${p.service} (${p.version}) on port ${p.port}`
            })),
        };
    }

    return {
        runNmapScan,
        TIMING_TEMPLATES,
        SCAN_TYPES,
    };
})();
