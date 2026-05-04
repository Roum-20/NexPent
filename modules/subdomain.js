/* ============================================
   NexPent — Subdomain Enumeration Module
   REAL-TIME: Uses DNS-over-HTTPS (DoH) APIs
   to resolve actual subdomains live.
   ============================================ */

const SubdomainModule = (() => {
    const wordlists = {
        small: [
            "www", "mail", "ftp", "smtp", "pop", "ns1", "ns2", "dns", "mx",
            "webmail", "admin", "portal", "blog", "shop", "api", "dev",
            "staging", "test", "beta", "demo", "app", "mobile", "m",
            "cdn", "static", "media", "img", "images", "assets", "upload",
            "vpn", "remote", "gateway", "proxy", "firewall", "ssh",
            "db", "database", "mysql", "postgres", "redis", "mongo", "elastic",
            "git", "svn", "jenkins", "ci", "cd", "build", "deploy",
            "status", "monitor", "grafana", "metrics", "logs", "kibana",
            "help", "support", "docs", "wiki", "kb", "forum", "community",
            "auth", "login", "sso", "oauth", "id", "accounts", "signup",
            "payment", "billing", "invoice", "checkout", "store", "cart",
            "email", "newsletter", "marketing", "crm", "hr", "erp",
            "intranet", "internal", "corp", "office", "teams", "slack",
            "chat", "messaging", "notifications", "push", "websocket",
            "search", "analytics", "tracking", "events", "report",
            "video", "stream", "live", "broadcast", "rtmp", "hls",
            "s3", "backup", "archive", "storage", "vault", "secret",
            "sandbox", "preview", "uat", "qa", "prod", "production",
            "v1", "v2", "legacy", "old", "new", "next",
        ],
        medium: [], // Will be generated
        large: [], // Will be generated
    };

    // Generate medium and large wordlists
    const extraWords = [
        "server", "host", "node", "cluster", "edge", "origin",
        "panel", "dashboard", "console", "manage", "manager",
        "api-gateway", "api-v1", "api-v2", "rest", "graphql", "grpc",
        "ws", "wss", "socket", "mqtt", "amqp", "rabbitmq", "kafka",
        "cache", "memcached", "varnish", "haproxy", "nginx", "apache",
        "docker", "k8s", "kubernetes", "swarm", "rancher", "portainer",
        "terraform", "ansible", "puppet", "chef", "vault-server",
        "prometheus", "alertmanager", "pagerduty", "opsgenie", "datadog",
        "sentry", "bugsnag", "rollbar", "newrelic", "apm",
        "ldap", "ad", "radius", "kerberos", "saml", "oidc",
        "proxy-east", "proxy-west", "us-east", "us-west", "eu-west", "ap-south",
        "cdn1", "cdn2", "edge1", "edge2", "lb1", "lb2",
        "web1", "web2", "web3", "app1", "app2", "app3",
        "db1", "db2", "db-master", "db-slave", "db-replica",
        "worker", "queue", "job", "cron", "scheduler", "task",
        "oauth2", "token", "jwt", "session", "cookie",
        "download", "release", "update", "patch", "hotfix",
        "partner", "vendor", "supplier", "client", "customer",
        "stage1", "stage2", "stage3", "canary", "blue", "green",
        "primary", "secondary", "tertiary", "fallback", "dr",
        "lab", "research", "experiment", "poc", "prototype",
        "repo", "registry", "artifact", "nexus", "sonar", "sonarqube",
        "jira", "confluence", "bitbucket", "gitlab", "github",
        "mailserver", "exchange", "postfix", "dovecot", "imap",
        "dns1", "dns2", "ns3", "ns4", "resolver",
        "ntp", "time", "snmp", "syslog", "logstash", "fluentd",
        "minio", "ceph", "gluster", "nfs", "iscsi", "san",
        "pki", "ca", "cert", "certificate", "ssl", "tls",
        "waf", "ids", "ips", "siem", "splunk", "qradar",
        "pentest", "scan", "audit", "compliance", "security",
        "dev1", "dev2", "dev3", "test1", "test2", "qa1", "qa2",
        "pre-prod", "preprod", "integration", "acceptance",
        "catalog", "inventory", "order", "shipping", "tracking-sys",
        "content", "cms", "wp", "wordpress", "drupal", "joomla",
        "magento", "shopify", "woocommerce", "prestashop",
    ];

    wordlists.medium = [...wordlists.small, ...extraWords];
    wordlists.large = [...wordlists.medium,
    ...Array.from({ length: 200 }, (_, i) => `host${i + 1}`),
    ...Array.from({ length: 50 }, (_, i) => `server${i + 1}`),
    ...Array.from({ length: 50 }, (_, i) => `node${i + 1}`),
    ...Array.from({ length: 26 }, (_, i) => String.fromCharCode(97 + i)),
    ];

    /**
     * Real DNS lookup using DNS-over-HTTPS (DoH).
     * Uses Google and Cloudflare DoH endpoints.
     */
    async function dnsLookup(subdomain) {
        const dohProviders = [
            `https://dns.google/resolve?name=${encodeURIComponent(subdomain)}&type=A`,
            `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(subdomain)}&type=A`,
        ];

        for (const url of dohProviders) {
            try {
                const controller = new AbortController();
                const timer = setTimeout(() => controller.abort(), 5000);

                const resp = await fetch(url, {
                    headers: { "Accept": "application/dns-json" },
                    signal: controller.signal,
                });
                clearTimeout(timer);

                if (!resp.ok) continue;

                const data = await resp.json();

                if (data.Status === 0 && data.Answer && data.Answer.length > 0) {
                    // Status 0 = NOERROR — domain exists
                    const aRecords = data.Answer.filter(r => r.type === 1); // Type 1 = A record
                    const cnameRecords = data.Answer.filter(r => r.type === 5); // Type 5 = CNAME
                    const aaaaRecords = data.Answer.filter(r => r.type === 28); // Type 28 = AAAA

                    let ip = "N/A";
                    let recordType = "A";

                    if (aRecords.length > 0) {
                        ip = aRecords[0].data;
                        recordType = "A";
                    } else if (cnameRecords.length > 0) {
                        ip = cnameRecords[0].data;
                        recordType = "CNAME";
                    } else if (aaaaRecords.length > 0) {
                        ip = aaaaRecords[0].data;
                        recordType = "AAAA";
                    } else {
                        ip = data.Answer[0].data;
                        recordType = `TYPE${data.Answer[0].type}`;
                    }

                    return { exists: true, ip, recordType, ttl: data.Answer[0].TTL || 0 };
                }

                // Status 3 = NXDOMAIN — domain does not exist
                if (data.Status === 3) {
                    return { exists: false };
                }

                // Other status codes
                return { exists: false };
            } catch (err) {
                // Try next provider
                continue;
            }
        }

        return { exists: false, error: "All DoH providers failed" };
    }

    /**
     * Check HTTP status of a found subdomain
     */
    async function checkHTTPStatus(subdomain) {
        for (const proto of ["https", "http"]) {
            try {
                const controller = new AbortController();
                const timer = setTimeout(() => controller.abort(), 4000);

                const resp = await fetch(`${proto}://${subdomain}/`, {
                    method: "HEAD",
                    mode: "no-cors",
                    signal: controller.signal,
                });
                clearTimeout(timer);

                // no-cors mode gives opaque response, but at least we know it's reachable
                return `${proto.toUpperCase()} reachable`;
            } catch {
                continue;
            }
        }
        return "No HTTP";
    }

    async function enumerate(config, outputEl, progressEl, fillEl, textEl) {
        const { domain, wordlistSize, resolveDNS } = config;
        const wordlist = wordlists[wordlistSize] || wordlists.medium;

        const results = {
            domain,
            subdomains: [],
            total: wordlist.length,
            checked: 0,
        };

        progressEl.style.display = "flex";

        addLine(outputEl, "info", "[SCAN]", `REAL-TIME subdomain enumeration for: ${domain}`);
        addLine(outputEl, "info", "[INFO]", `Wordlist: ${wordlistSize} (${wordlist.length} entries)`);
        addLine(outputEl, "info", "[INFO]", `DNS Resolution: ${resolveDNS ? "Enabled" : "Disabled"}`);
        addLine(outputEl, "warning", "[LIVE]", "⚡ Live DNS lookups via DNS-over-HTTPS (Google/Cloudflare DoH)");
        addLine(outputEl, "system", "[SYS]", "─".repeat(60));

        // Phase 1: Certificate Transparency search (crt.sh)
        addLine(outputEl, "info", "[PHASE]", "Phase 1: Certificate Transparency log search (crt.sh)...");
        try {
            const ctResults = await searchCertTransparency(domain);
            if (ctResults.length > 0) {
                addLine(outputEl, "success", "[CT]", `Found ${ctResults.length} subdomain(s) from CT logs`);
                for (const sub of ctResults) {
                    // Check if already in our wordlist
                    const prefix = sub.replace(`.${domain}`, "");
                    if (!wordlist.includes(prefix)) {
                        wordlist.push(prefix);
                    }
                    // Do DNS verification
                    if (resolveDNS) {
                        const dns = await dnsLookup(sub);
                        if (dns.exists) {
                            const httpStatus = await checkHTTPStatus(sub);
                            results.subdomains.push({
                                subdomain: sub,
                                ip: dns.ip,
                                recordType: dns.recordType,
                                status: httpStatus,
                                source: "CT Log",
                            });
                            addLine(outputEl, "found", "[FOUND]", `${sub} (from CT log)`);
                            addLine(outputEl, "success", "[DNS]", `  → ${dns.recordType}: ${dns.ip} | ${httpStatus}`);
                        }
                    } else {
                        results.subdomains.push({
                            subdomain: sub,
                            ip: "N/A",
                            recordType: "CT",
                            status: "From CT Log",
                            source: "CT Log",
                        });
                        addLine(outputEl, "found", "[FOUND]", `${sub} (CT log)`);
                    }
                }
            } else {
                addLine(outputEl, "system", "[CT]", "No additional subdomains from CT logs");
            }
        } catch (err) {
            addLine(outputEl, "warning", "[CT]", `CT log search failed: ${err.message}`);
        }

        // Phase 2: DNS brute-force with DoH
        addLine(outputEl, "system", "[SYS]", "─".repeat(40));
        addLine(outputEl, "info", "[PHASE]", "Phase 2: DNS brute-force enumeration via DoH...");

        // Process in batches for concurrency
        const batchSize = 5; // DoH rate limiting friendly
        for (let i = 0; i < wordlist.length; i += batchSize) {
            const batch = wordlist.slice(i, Math.min(i + batchSize, wordlist.length));
            const batchPromises = batch.map(async (sub) => {
                const fullDomain = `${sub}.${domain}`;
                results.checked++;

                const pct = Math.round((results.checked / wordlist.length) * 100);
                fillEl.style.width = pct + "%";
                textEl.textContent = pct + "%";

                // Skip if already found from CT logs
                if (results.subdomains.some(s => s.subdomain === fullDomain)) {
                    return;
                }

                const dns = await dnsLookup(fullDomain);

                if (dns.exists) {
                    let httpStatus = "N/A";
                    if (resolveDNS) {
                        httpStatus = await checkHTTPStatus(fullDomain);
                    }

                    const result = {
                        subdomain: fullDomain,
                        ip: dns.ip,
                        recordType: dns.recordType,
                        status: httpStatus,
                        source: "DNS Brute-force",
                    };

                    // Avoid duplicates
                    if (!results.subdomains.some(s => s.subdomain === fullDomain)) {
                        results.subdomains.push(result);

                        addLine(outputEl, "found", "[FOUND]", `${fullDomain}`);
                        if (resolveDNS) {
                            addLine(outputEl, "success", "[DNS]", `  → ${dns.recordType}: ${dns.ip} | ${httpStatus}`);
                        }
                    }
                }
            });

            await Promise.all(batchPromises);

            // Show progress periodically
            if ((i + batchSize) % 50 === 0 || i + batchSize >= wordlist.length) {
                const checked = Math.min(i + batchSize, wordlist.length);
                addLine(outputEl, "system", `[${checked}/${wordlist.length}]`, `Checked ${checked} entries, found ${results.subdomains.length} subdomains...`);
            }
        }

        addLine(outputEl, "system", "[SYS]", "─".repeat(60));
        addLine(outputEl, "info", "[DONE]", `Enumeration complete!`);
        addLine(outputEl, "info", "[STAT]", `Checked: ${results.checked} | Found: ${results.subdomains.length} subdomains`);

        if (results.subdomains.length > 0) {
            addLine(outputEl, "system", "[SYS]", "─".repeat(60));
            addLine(outputEl, "info", "[LIST]", "Discovered subdomains:");
            results.subdomains.forEach((s, i) => {
                addLine(outputEl, "found", `[${i + 1}]`, `${s.subdomain} → ${s.ip} (${s.recordType}) [${s.source}]`);
            });
        }

        return results;
    }

    /**
     * Search Certificate Transparency logs via crt.sh
     */
    async function searchCertTransparency(domain) {
        try {
            const controller = new AbortController();
            const timer = setTimeout(() => controller.abort(), 10000);

            const resp = await fetch(
                `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`,
                { signal: controller.signal }
            );
            clearTimeout(timer);

            if (!resp.ok) return [];

            const data = await resp.json();
            const subdomains = new Set();

            for (const entry of data) {
                const names = (entry.name_value || "").split("\n");
                for (const name of names) {
                    const clean = name.trim().toLowerCase().replace(/^\*\./, "");
                    if (clean.endsWith(`.${domain}`) && clean !== domain && !clean.includes("*")) {
                        subdomains.add(clean);
                    }
                }
            }

            // Limit to first 100 unique subdomains to avoid overload
            return Array.from(subdomains).slice(0, 100);
        } catch {
            return [];
        }
    }

    function exportResults(results) {
        let text = `# Subdomain Enumeration Report\n`;
        text += `# Target: ${results.domain}\n`;
        text += `# Date: ${new Date().toISOString()}\n`;
        text += `# Found: ${results.subdomains.length} subdomains\n`;
        text += `# Method: Real-time DNS-over-HTTPS + Certificate Transparency\n\n`;

        results.subdomains.forEach((s) => {
            text += `${s.subdomain}\t${s.ip}\t${s.recordType}\t${s.status}\t${s.source}\n`;
        });

        const blob = new Blob([text], { type: "text/plain" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `subdomains_${results.domain}_${Date.now()}.txt`;
        a.click();
        URL.revokeObjectURL(url);
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

    return { enumerate, exportResults };
})();
