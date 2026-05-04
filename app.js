/* ============================================
   NexPent — Main Application Controller
   ============================================ */

(function () {
    "use strict";

    // ========== STATE ==========
    const state = {
        currentPage: "dashboard",
        scanning: false,
        scanData: {
            totalScans: 0,
            sqli: null,
            xss: null,
            bf: null,
            code: null,
            sub: null,
            port: null,
            nmap: null,
            malware: null,
            cve: [],
        },
        stats: {
            scans: 0,
            vulns: 0,
            critical: 0,
            reports: 0,
        },
        history: [],
    };

    // ========== DOM REFS ==========
    const $ = (sel) => document.querySelector(sel);
    const $$ = (sel) => document.querySelectorAll(sel);

    const sidebar = $("#sidebar");
    const mainContent = $("#mainContent");
    const sidebarToggle = $("#sidebarToggle");
    const mobileMenuBtn = $("#mobileMenuBtn");

    // ========== NAVIGATION ==========
    function navigateTo(page) {
        state.currentPage = page;

        // Update nav items
        $$(".nav-item").forEach((el) => el.classList.remove("active"));
        const navItem = $(`[data-page="${page}"]`);
        if (navItem) navItem.classList.add("active");

        // Update pages
        $$(".page").forEach((el) => el.classList.remove("active"));
        const pageEl = $(`#page-${page}`);
        if (pageEl) pageEl.classList.add("active");

        // Update breadcrumb
        const pageNames = {
            dashboard: "Dashboard",
            sqli: "SQL Injection Scanner",
            xss: "XSS Detection",
            bruteforce: "Brute-Force Tester",
            codescanner: "Static Code Scanner",
            subdomain: "Subdomain Enumeration",
            portscan: "Port Scanner",
            cve: "CVE Lookup",
            nmap: "Nmap Scanner",
            malware: "Malware Analysis",
            aichat: "AI Security Chatbot",
            owasp: "OWASP Top 10",
            reports: "Report Generator",
        };
        $("#breadcrumbText").textContent = pageNames[page] || page;

        // Close mobile menu
        sidebar.classList.remove("mobile-open");
    }

    // Sidebar navigation clicks
    $$(".nav-item").forEach((item) => {
        item.addEventListener("click", (e) => {
            e.preventDefault();
            const page = item.dataset.page;
            if (page) navigateTo(page);
        });
    });

    // Quick launch buttons
    $$(".quick-btn").forEach((btn) => {
        btn.addEventListener("click", () => {
            const page = btn.dataset.page;
            if (page) navigateTo(page);
        });
    });

    // New Scan button
    const newScanBtn = $("#newScanBtn");
    if (newScanBtn) {
        newScanBtn.addEventListener("click", () => navigateTo("sqli"));
    }

    // Sidebar toggle
    if (sidebarToggle) {
        sidebarToggle.addEventListener("click", () => {
            sidebar.classList.toggle("collapsed");
        });
    }

    // Maximize / Fullscreen
    const maximizeBtn = $("#maximizeBtn");
    if (maximizeBtn) {
        maximizeBtn.addEventListener("click", () => {
            if (!document.fullscreenElement) {
                document.documentElement.requestFullscreen().catch((err) => {
                    showToast("error", "Fullscreen Error", err.message);
                });
                maximizeBtn.innerHTML = '<i class="fas fa-compress"></i>';
                document.body.classList.add("is-maximized");
            } else {
                if (document.exitFullscreen) {
                    document.exitFullscreen();
                    maximizeBtn.innerHTML = '<i class="fas fa-expand"></i>';
                    document.body.classList.remove("is-maximized");
                }
            }
        });
    }

    // Reset icon on escape key or outside exit
    document.addEventListener("fullscreenchange", () => {
        if (!document.fullscreenElement && maximizeBtn) {
            maximizeBtn.innerHTML = '<i class="fas fa-expand"></i>';
            document.body.classList.remove("is-maximized");
        }
    });

    const sidebarMaximize = $("#sidebarMaximize");
    if (sidebarMaximize) {
        sidebarMaximize.addEventListener("click", () => {
            maximizeBtn.click(); // Trigger the same logic
        });
    }

    // Mobile menu
    if (mobileMenuBtn) {
        mobileMenuBtn.addEventListener("click", () => {
            sidebar.classList.toggle("mobile-open");
        });
    }

    // Search functionality
    const moduleSearch = $("#moduleSearch");
    if (moduleSearch) {
        moduleSearch.addEventListener("input", (e) => {
            const query = e.target.value.toLowerCase();
            $$(".nav-item").forEach((item) => {
                const text = item.textContent.toLowerCase();
                item.style.display = text.includes(query) || !query ? "" : "none";
            });
        });
    }

    // ========== TOAST NOTIFICATIONS ==========
    function showToast(type, title, message) {
        const container = $("#toastContainer");
        const icons = {
            info: "fa-circle-info",
            success: "fa-circle-check",
            warning: "fa-triangle-exclamation",
            error: "fa-circle-xmark",
        };

        const toast = document.createElement("div");
        toast.className = `toast ${type}`;
        toast.innerHTML = `
            <i class="fas ${icons[type]} toast-icon"></i>
            <div class="toast-content">
                <div class="toast-title">${title}</div>
                <div class="toast-msg">${message}</div>
            </div>
            <button class="toast-close"><i class="fas fa-xmark"></i></button>
        `;

        container.appendChild(toast);

        toast.querySelector(".toast-close").addEventListener("click", () => {
            toast.classList.add("removing");
            setTimeout(() => toast.remove(), 300);
        });

        setTimeout(() => {
            if (toast.parentElement) {
                toast.classList.add("removing");
                setTimeout(() => toast.remove(), 300);
            }
        }, 4000);
    }

    // ========== STATS UPDATE ==========
    function updateStats() {
        const statScans = $("#stat-scans .stat-value");
        const statVulns = $("#stat-vulns .stat-value");
        const statCritical = $("#stat-critical .stat-value");
        const statReports = $("#stat-reports .stat-value");

        if (statScans) animateNumber(statScans, state.stats.scans);
        if (statVulns) animateNumber(statVulns, state.stats.vulns);
        if (statCritical) animateNumber(statCritical, state.stats.critical);
        if (statReports) animateNumber(statReports, state.stats.reports);

        // Persist snapshot to localStorage so stats survive refresh
        if (typeof ScanStore !== "undefined") {
            const store = ScanStore.load() || { stats: {}, history: [], scanData: {} };
            store.stats = { ...state.stats };
            store.scanData = { ...state.scanData };
            // Ensure history is never lost during stats update
            if (!store.history) store.history = [];
            store.savedAt = Date.now();

            try {
                localStorage.setItem(
                    sessionStorage.getItem("nexpent_session")
                        ? `nexpent_scandata_${JSON.parse(sessionStorage.getItem("nexpent_session")).id}`
                        : "nexpent_scandata_guest",
                    JSON.stringify(store)
                );
            } catch (e) {
                console.warn("[App] Could not persist stats:", e);
            }
        }
    }

    function animateNumber(el, target) {
        const current = parseInt(el.textContent) || 0;
        if (current === target) return;

        const duration = 500;
        const steps = 20;
        const increment = (target - current) / steps;
        let step = 0;

        const interval = setInterval(() => {
            step++;
            el.textContent = Math.round(current + increment * step);
            if (step >= steps) {
                el.textContent = target;
                clearInterval(interval);
            }
        }, duration / steps);
    }

    // ========== HISTORY ==========
    function addToHistory(type, title, target) {
        const entry = {
            type,
            title,
            target,
            status: "complete",
        };
        // Persist to localStorage via ScanStore
        if (typeof ScanStore !== "undefined") ScanStore.addHistory(entry);
        state.history.unshift({ ...entry, time: new Date().toLocaleTimeString() });
        if (state.history.length > 50) state.history.pop();
        renderHistory();
    }

    function renderHistory() {
        const container = $("#scanHistory");
        if (!container) return;

        if (state.history.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <i class="fas fa-satellite-dish"></i>
                    <p>No scans performed yet</p>
                    <span>Launch a module to begin</span>
                </div>
            `;
            return;
        }

        container.innerHTML = state.history
            .map(
                (h) => `
            <div class="history-item">
                <div class="history-icon ${h.type}"><i class="fas ${getTypeIcon(h.type)}"></i></div>
                <div class="history-info">
                    <div class="history-title">${h.title}</div>
                    <div class="history-time">${h.date ? h.date + ' ' : ''}${h.time}</div>
                </div>
                <span class="history-status ${h.status}">${h.status}</span>
            </div>
        `
            )
            .join("");
    }

    function getTypeIcon(type) {
        const icons = {
            sqli: "fa-database",
            xss: "fa-code",
            bf: "fa-key",
            code: "fa-file-code",
            sub: "fa-globe",
            port: "fa-ethernet",
            nmap: "fa-network-wired",
            malware: "fa-biohazard",
            cve: "fa-bug",
        };
        return icons[type] || "fa-circle";
    }

    // ========== ACTIVITY FEED ==========
    function addToFeed(type, msg) {
        const feed = $("#activityFeed");
        if (!feed) return;

        const tags = { info: "[INFO]", success: "[OK]", warning: "[WARN]", error: "[ALERT]", system: "[SYS]" };
        const line = document.createElement("div");
        line.className = `terminal-line ${type}`;
        line.innerHTML = `<span class="time">${tags[type] || "[LOG]"}</span><span class="msg">${msg}</span>`;
        feed.appendChild(line);
        feed.scrollTop = feed.scrollHeight;
    }

    // Clear feed button
    const clearFeedBtn = $("#clearFeedBtn");
    if (clearFeedBtn) {
        clearFeedBtn.addEventListener("click", () => {
            const feed = $("#activityFeed");
            if (feed) feed.innerHTML = `<div class="terminal-line system"><span class="time">[SYS]</span><span class="msg">Feed cleared.</span></div>`;
        });
    }

    // ========== SQL INJECTION SCANNER ==========
    const sqliGetBtn = $("#sqliGetBtn");
    const sqliPostBtn = $("#sqliPostBtn");
    const sqliScanBtn = $("#sqliScanBtn");
    const sqliClearBtn = $("#sqliClearBtn");
    const sqliCopyBtn = $("#sqliCopyBtn");

    if (sqliGetBtn && sqliPostBtn) {
        sqliGetBtn.addEventListener("click", () => {
            sqliGetBtn.classList.add("active");
            sqliPostBtn.classList.remove("active");
            $("#sqliPostData").style.display = "none";
        });
        sqliPostBtn.addEventListener("click", () => {
            sqliPostBtn.classList.add("active");
            sqliGetBtn.classList.remove("active");
            $("#sqliPostData").style.display = "block";
        });
    }

    if (sqliScanBtn) {
        sqliScanBtn.addEventListener("click", async () => {
            const url = $("#sqliUrl").value.trim();
            if (!url) {
                showToast("error", "Missing Target", "Please enter a target URL.");
                return;
            }
            if (state.scanning) {
                showToast("warning", "Scan Active", "A scan is already running. Please wait.");
                return;
            }

            state.scanning = true;
            sqliScanBtn.disabled = true;
            sqliScanBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Scanning...';

            const config = {
                url,
                method: sqliGetBtn.classList.contains("active") ? "GET" : "POST",
                postData: $("#sqliPostBody")?.value || "",
                level: $("#sqliLevel").value,
                customPayloads: $("#sqliCustomPayloads").value,
            };

            addToFeed("info", `SQLi scan started on ${url}`);

            try {
                const results = await ScannerModule.runSQLiScan(
                    config,
                    $("#sqliOutput"),
                    $("#sqliProgress"),
                    $("#sqliFill"),
                    $("#sqliProgressText")
                );

                state.scanData.sqli = results;
                state.scanData.totalScans++;
                state.stats.scans++;
                state.stats.vulns += results.vulns.length;
                state.stats.critical += results.vulns.filter((v) => v.severity === "critical").length;
                updateStats();

                addToHistory("sqli", `SQLi Scan: ${url}`, url);
                addToFeed(results.vulns.length > 0 ? "error" : "success",
                    `SQLi scan complete: ${results.vulns.length} vulnerabilities found`);

                showToast(
                    results.vulns.length > 0 ? "error" : "success",
                    "SQL Injection Scan Complete",
                    `${results.vulns.length} vulnerabilities found in ${results.tested} tests`
                );
            } catch (err) {
                showToast("error", "Scan Error", err.message);
                addToFeed("error", `SQLi scan failed: ${err.message}`);
            }

            state.scanning = false;
            sqliScanBtn.disabled = false;
            sqliScanBtn.innerHTML = '<i class="fas fa-crosshairs"></i> Launch SQL Injection Scan';
        });
    }

    if (sqliClearBtn) sqliClearBtn.addEventListener("click", () => clearOutput("sqliOutput", "sqliProgress"));
    if (sqliCopyBtn) sqliCopyBtn.addEventListener("click", () => copyOutput("sqliOutput"));

    // ========== XSS SCANNER ==========
    const xssScanBtn = $("#xssScanBtn");
    const xssClearBtn = $("#xssClearBtn");
    const xssCopyBtn = $("#xssCopyBtn");

    if (xssScanBtn) {
        xssScanBtn.addEventListener("click", async () => {
            const url = $("#xssUrl").value.trim();
            const param = $("#xssParam").value.trim();
            if (!url) {
                showToast("error", "Missing Target", "Please enter a target URL.");
                return;
            }
            if (!param) {
                showToast("error", "Missing Parameter", "Please enter a parameter name to test.");
                return;
            }
            if (state.scanning) {
                showToast("warning", "Scan Active", "A scan is already running.");
                return;
            }

            state.scanning = true;
            xssScanBtn.disabled = true;
            xssScanBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Scanning...';

            const config = {
                url,
                param,
                type: $("#xssType").value,
                customPayloads: $("#xssCustomPayloads").value,
            };

            addToFeed("info", `XSS scan started on ${url} (param: ${param})`);

            try {
                const results = await ScannerModule.runXSSScan(
                    config,
                    $("#xssOutput"),
                    $("#xssProgress"),
                    $("#xssFill"),
                    $("#xssProgressText")
                );

                state.scanData.xss = results;
                state.scanData.totalScans++;
                state.stats.scans++;
                state.stats.vulns += results.vulns.length;
                state.stats.critical += results.vulns.filter((v) => v.severity === "critical").length;
                updateStats();

                addToHistory("xss", `XSS Scan: ${url}`, url);
                addToFeed(results.vulns.length > 0 ? "error" : "success",
                    `XSS scan complete: ${results.vulns.length} vulnerabilities found`);

                showToast(
                    results.vulns.length > 0 ? "error" : "success",
                    "XSS Scan Complete",
                    `${results.vulns.length} vulnerabilities found`
                );
            } catch (err) {
                showToast("error", "Scan Error", err.message);
            }

            state.scanning = false;
            xssScanBtn.disabled = false;
            xssScanBtn.innerHTML = '<i class="fas fa-crosshairs"></i> Launch XSS Scan';
        });
    }

    if (xssClearBtn) xssClearBtn.addEventListener("click", () => clearOutput("xssOutput", "xssProgress"));
    if (xssCopyBtn) xssCopyBtn.addEventListener("click", () => copyOutput("xssOutput"));

    // ========== BRUTE-FORCE TESTER ==========
    const bfScanBtn = $("#bfScanBtn");
    const bfClearBtn = $("#bfClearBtn");

    if (bfScanBtn) {
        bfScanBtn.addEventListener("click", async () => {
            const url = $("#bfUrl").value.trim();
            if (!url) {
                showToast("error", "Missing Target", "Please enter a login URL.");
                return;
            }
            if (state.scanning) {
                showToast("warning", "Scan Active", "A scan is already running.");
                return;
            }

            state.scanning = true;
            bfScanBtn.disabled = true;
            bfScanBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Testing...';

            const config = {
                url,
                userField: $("#bfUserField").value,
                passField: $("#bfPassField").value,
                usernames: $("#bfUsernames").value,
                passwords: $("#bfPasswords").value,
                failText: $("#bfFailText").value,
            };

            addToFeed("info", `Brute-force test started on ${url}`);

            try {
                const results = await BruteForceModule.runBruteForce(
                    config,
                    $("#bfOutput"),
                    $("#bfProgress"),
                    $("#bfFill"),
                    $("#bfProgressText")
                );

                state.scanData.bf = results;
                state.scanData.totalScans++;
                state.stats.scans++;
                state.stats.vulns += results.found.length;
                updateStats();

                addToHistory("bf", `Brute-Force: ${url}`, url);
                addToFeed(results.found.length > 0 ? "warning" : "success",
                    `Brute-force test complete: ${results.found.length} credentials found`);

                showToast(
                    results.found.length > 0 ? "warning" : "success",
                    "Brute-Force Test Complete",
                    `${results.found.length} credentials found in ${results.tested} attempts`
                );
            } catch (err) {
                showToast("error", "Test Error", err.message);
            }

            state.scanning = false;
            bfScanBtn.disabled = false;
            bfScanBtn.innerHTML = '<i class="fas fa-unlock"></i> Launch Brute-Force Test';
        });
    }

    if (bfClearBtn) bfClearBtn.addEventListener("click", () => clearOutput("bfOutput", "bfProgress"));

    // ========== STATIC CODE SCANNER ==========
    const codeScanBtn = $("#codeScanBtn");
    const codeClearBtn = $("#codeClearBtn");
    const codeFileInput = $("#codeFileInput");
    const uploadZone = $("#uploadZone");

    // Drag and drop
    if (uploadZone) {
        ["dragenter", "dragover"].forEach((event) => {
            uploadZone.addEventListener(event, (e) => {
                e.preventDefault();
                uploadZone.classList.add("dragover");
            });
        });
        ["dragleave", "drop"].forEach((event) => {
            uploadZone.addEventListener(event, (e) => {
                e.preventDefault();
                uploadZone.classList.remove("dragover");
            });
        });
        uploadZone.addEventListener("drop", (e) => {
            const files = e.dataTransfer.files;
            if (files.length > 0) handleFileUpload(files[0]);
        });
    }

    if (codeFileInput) {
        codeFileInput.addEventListener("change", (e) => {
            if (e.target.files.length > 0) handleFileUpload(e.target.files[0]);
        });
    }

    function handleFileUpload(file) {
        const reader = new FileReader();
        reader.onload = (e) => {
            const codePaste = $("#codePasteInput");
            if (codePaste) codePaste.value = e.target.result;
            showToast("info", "File Loaded", `${file.name} loaded for analysis.`);

            // Auto-detect language
            const lang = CodeScannerModule.detectLanguage(e.target.result, file.name);
            const langSelect = $("#codeLanguage");
            if (langSelect) {
                for (const opt of langSelect.options) {
                    if (opt.value === lang) { opt.selected = true; break; }
                }
            }
        };
        reader.readAsText(file);
    }

    if (codeScanBtn) {
        codeScanBtn.addEventListener("click", () => {
            const code = $("#codePasteInput").value.trim();
            if (!code) {
                showToast("error", "No Code", "Please upload a file or paste code to analyze.");
                return;
            }

            const language = $("#codeLanguage").value;
            const results = CodeScannerModule.analyzeCode(code, language);
            CodeScannerModule.renderResults(results, $("#codeOutput"));

            state.scanData.code = results;
            state.scanData.totalScans++;
            state.stats.scans++;
            state.stats.vulns += results.findings.length;
            state.stats.critical += results.findings.filter((f) => f.severity === "critical").length;
            updateStats();

            addToHistory("code", `Code Scan: ${results.language}`, results.filename);
            addToFeed(results.findings.length > 0 ? "warning" : "success",
                `Code analysis: ${results.findings.length} issues, score ${results.score}/100`);

            showToast(
                results.score >= 80 ? "success" : results.score >= 50 ? "warning" : "error",
                "Code Analysis Complete",
                `Score: ${results.score}/100 — ${results.findings.length} issues found`
            );
        });
    }

    if (codeClearBtn) codeClearBtn.addEventListener("click", () => clearOutput("codeOutput"));

    // ========== SUBDOMAIN ENUMERATION ==========
    const subScanBtn = $("#subScanBtn");
    const subClearBtn = $("#subClearBtn");
    const subExportBtn = $("#subExportBtn");

    if (subScanBtn) {
        subScanBtn.addEventListener("click", async () => {
            const domain = $("#subDomain").value.trim();
            if (!domain) {
                showToast("error", "Missing Domain", "Please enter a target domain.");
                return;
            }
            if (state.scanning) {
                showToast("warning", "Scan Active", "A scan is already running.");
                return;
            }

            state.scanning = true;
            subScanBtn.disabled = true;
            subScanBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Enumerating...';

            const config = {
                domain,
                wordlistSize: $("#subWordlist").value,
                resolveDNS: $("#subResolve").checked,
            };

            addToFeed("info", `Subdomain enumeration started for ${domain}`);

            try {
                const results = await SubdomainModule.enumerate(
                    config,
                    $("#subOutput"),
                    $("#subProgress"),
                    $("#subFill"),
                    $("#subProgressText")
                );

                state.scanData.sub = results;
                state.scanData.totalScans++;
                state.stats.scans++;
                updateStats();

                addToHistory("sub", `Subdomains: ${domain}`, domain);
                addToFeed("success", `Subdomain enum complete: ${results.subdomains.length} found for ${domain}`);

                showToast("success", "Enumeration Complete", `${results.subdomains.length} subdomains discovered`);
            } catch (err) {
                showToast("error", "Enumeration Error", err.message);
            }

            state.scanning = false;
            subScanBtn.disabled = false;
            subScanBtn.innerHTML = '<i class="fas fa-magnifying-glass"></i> Enumerate Subdomains';
        });
    }

    if (subClearBtn) subClearBtn.addEventListener("click", () => clearOutput("subOutput", "subProgress"));
    if (subExportBtn) {
        subExportBtn.addEventListener("click", () => {
            if (state.scanData.sub) {
                SubdomainModule.exportResults(state.scanData.sub);
                showToast("success", "Exported", "Subdomain results exported to file.");
            } else {
                showToast("warning", "No Data", "Run an enumeration scan first.");
            }
        });
    }

    // ========== PORT SCANNER ==========
    const portScanBtn = $("#portScanBtn");
    const portClearBtn = $("#portClearBtn");

    if (portScanBtn) {
        portScanBtn.addEventListener("click", async () => {
            const host = $("#portHost").value.trim();
            if (!host) {
                showToast("error", "Missing Target", "Please enter a target host.");
                return;
            }
            if (state.scanning) {
                showToast("warning", "Scan Active", "A scan is already running.");
                return;
            }

            state.scanning = true;
            portScanBtn.disabled = true;
            portScanBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Scanning...';

            const config = {
                host,
                startPort: parseInt($("#portStart").value) || 1,
                endPort: parseInt($("#portEnd").value) || 1024,
                speed: $("#portSpeed").value,
                serviceDetection: $("#portService").checked,
            };

            addToFeed("info", `Port scan started on ${host} (${config.startPort}-${config.endPort})`);

            try {
                const results = await PortScannerModule.scanPorts(
                    config,
                    $("#portOutput"),
                    $("#portProgress"),
                    $("#portFill"),
                    $("#portProgressText")
                );

                state.scanData.port = results;
                state.scanData.totalScans++;
                state.stats.scans++;
                const highRisk = results.openPorts.filter((p) => p.risk === "high" || p.risk === "critical");
                state.stats.vulns += highRisk.length;
                state.stats.critical += results.openPorts.filter((p) => p.risk === "critical").length;
                updateStats();

                addToHistory("port", `Port Scan: ${host}`, host);
                addToFeed("success", `Port scan complete: ${results.openPorts.length} open ports on ${host}`);

                showToast("success", "Port Scan Complete", `${results.openPorts.length} open ports found`);
            } catch (err) {
                showToast("error", "Scan Error", err.message);
            }

            state.scanning = false;
            portScanBtn.disabled = false;
            portScanBtn.innerHTML = '<i class="fas fa-satellite-dish"></i> Start Port Scan';
        });
    }

    if (portClearBtn) portClearBtn.addEventListener("click", () => clearOutput("portOutput", "portProgress"));

    // ========== CVE LOOKUP ==========
    const cveLookupBtn = $("#cveLookupBtn");
    const cveClearBtn = $("#cveClearBtn");

    if (cveLookupBtn) {
        cveLookupBtn.addEventListener("click", async () => {
            const query = $("#cveQuery").value.trim();
            if (!query) {
                showToast("error", "Missing Query", "Please enter a CVE ID or keyword.");
                return;
            }

            const severity = $("#cveSeverity").value;
            const yearStart = parseInt($("#cveYearStart").value) || 2020;
            const yearEnd = parseInt($("#cveYearEnd").value) || 2026;

            cveLookupBtn.disabled = true;
            cveLookupBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Searching NVD...';
            addToFeed("info", `CVE lookup started for "${query}" (querying NIST NVD API)...`);

            try {
                const results = await CVELookupModule.search(query, severity, yearStart, yearEnd);
                CVELookupModule.renderResults(results, $("#cveOutput"));

                state.scanData.cve = results;
                state.scanData.totalScans++;
                state.stats.scans++;
                updateStats();

                addToHistory("cve", `CVE: ${query}`, query);
                addToFeed("info", `CVE lookup: ${results.length} results for "${query}"`);

                showToast("info", "CVE Lookup Complete", `${results.length} CVEs found for "${query}"`);
            } catch (err) {
                showToast("error", "CVE Lookup Error", err.message);
                addToFeed("error", `CVE lookup failed: ${err.message}`);
            }

            cveLookupBtn.disabled = false;
            cveLookupBtn.innerHTML = '<i class="fas fa-search"></i> Search CVE Database';
        });
    }

    if (cveClearBtn) {
        cveClearBtn.addEventListener("click", () => {
            const output = $("#cveOutput");
            if (output) {
                output.innerHTML = `<div class="empty-state"><i class="fas fa-database"></i><p>Search the CVE database</p><span>Enter a CVE ID or keyword</span></div>`;
            }
        });
    }

    // ========== NMAP SCANNER ==========
    const nmapScanBtn = $("#nmapScanBtn");
    const nmapClearBtn = $("#nmapClearBtn");
    const nmapCopyBtn = $("#nmapCopyBtn");
    const nmapTimingSelect = $("#nmapTiming");
    const nmapTimingFillBar = $("#nmapTimingFill");

    // Timing bar visual update
    const timingPercentMap = { T0: "0%", T1: "16%", T2: "33%", T3: "50%", T4: "75%", T5: "100%" };
    const timingColorMap = { T0: "#94a3b8", T1: "#60a5fa", T2: "#34d399", T3: "#fbbf24", T4: "#f97316", T5: "#ef4444" };

    if (nmapTimingSelect && nmapTimingFillBar) {
        nmapTimingSelect.addEventListener("change", () => {
            const val = nmapTimingSelect.value;
            nmapTimingFillBar.style.width = timingPercentMap[val] || "50%";
            nmapTimingFillBar.style.background = `linear-gradient(90deg, ${timingColorMap[val] || "#fbbf24"}, ${timingColorMap[val] || "#fbbf24"}88)`;
        });
        // Set initial state
        nmapTimingFillBar.style.background = `linear-gradient(90deg, #fbbf24, #fbbf2488)`;
    }

    if (nmapScanBtn) {
        nmapScanBtn.addEventListener("click", async () => {
            const target = $("#nmapTarget").value.trim();
            if (!target) {
                showToast("error", "Missing Target", "Please enter a target host or IP.");
                return;
            }
            if (state.scanning) {
                showToast("warning", "Scan in Progress", "Wait for the current scan to finish.");
                return;
            }

            state.scanning = true;
            nmapScanBtn.disabled = true;
            nmapScanBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Scanning...';

            const config = {
                target,
                scanType: $("#nmapScanType").value,
                timing: $("#nmapTiming").value,
                enableOS: $("#nmapEnableOS").checked,
                enableVersion: $("#nmapEnableVersion").checked,
                enableScripts: $("#nmapEnableScripts").checked,
            };

            addToFeed("info", `Nmap ${config.timing} ${config.scanType.toUpperCase()} scan started on ${target}`);

            try {
                const results = await NmapModule.runNmapScan(
                    config,
                    $("#nmapOutput"),
                    $("#nmapProgress"),
                    $("#nmapFill"),
                    $("#nmapProgressText")
                );

                state.scanData.nmap = results;

                const vulnCount = results.vulns ? results.vulns.length : 0;
                state.stats.scans++;
                state.stats.vulns += vulnCount;
                state.stats.critical += results.criticalCount || 0;
                updateStats();

                addToHistory("nmap", `Nmap ${config.timing} Scan`, target);
                addToFeed("success", `Nmap scan complete: ${results.openPorts.length} open ports, ${vulnCount} high-risk findings`);
                showToast("success", "Nmap Scan Complete", `${results.openPorts.length} open ports found on ${target}`);

                if (typeof ScanStore !== "undefined") ScanStore.saveScanResult("nmap", results);
            } catch (err) {
                addToFeed("error", `Nmap scan failed: ${err.message}`);
                showToast("error", "Scan Error", err.message);
            }

            state.scanning = false;
            nmapScanBtn.disabled = false;
            nmapScanBtn.innerHTML = '<i class="fas fa-satellite-dish"></i> Launch Nmap Scan';
        });
    }

    if (nmapClearBtn) nmapClearBtn.addEventListener("click", () => clearOutput("nmapOutput", "nmapProgress"));
    if (nmapCopyBtn) nmapCopyBtn.addEventListener("click", () => copyOutput("nmapOutput"));

    // ========== MALWARE ANALYSIS ==========
    const malwareDropZone = $("#malwareDropZone");
    const malwareFileInput = $("#malwareFileInput");
    const malwareScanBtn = $("#malwareScanBtn");
    const malwareClearBtn = $("#malwareClearBtn");
    const malwareCopyBtn = $("#malwareCopyBtn");
    const malwareRemoveBtn = $("#malwareRemoveFile");
    let malwareSelectedFile = null;

    function setMalwareFile(file) {
        malwareSelectedFile = file;
        const info = $("#malwareFileInfo");
        const zone = $("#malwareDropZone");
        if (info) {
            $("#malwareFileName").textContent = file.name;
            $("#malwareFileSize").textContent = MalwareAnalyzer.formatBytes(file.size);
            info.style.display = "flex";
        }
        if (zone) zone.style.display = "none";
        if (malwareScanBtn) malwareScanBtn.disabled = false;
    }

    function clearMalwareFile() {
        malwareSelectedFile = null;
        const info = $("#malwareFileInfo");
        const zone = $("#malwareDropZone");
        if (info) info.style.display = "none";
        if (zone) zone.style.display = "flex";
        if (malwareScanBtn) malwareScanBtn.disabled = true;
        if (malwareFileInput) malwareFileInput.value = "";
    }

    if (malwareDropZone) {
        malwareDropZone.addEventListener("click", () => malwareFileInput?.click());
        malwareDropZone.addEventListener("dragover", (e) => {
            e.preventDefault();
            malwareDropZone.classList.add("drag-over");
        });
        malwareDropZone.addEventListener("dragleave", () => {
            malwareDropZone.classList.remove("drag-over");
        });
        malwareDropZone.addEventListener("drop", (e) => {
            e.preventDefault();
            malwareDropZone.classList.remove("drag-over");
            if (e.dataTransfer.files.length > 0) setMalwareFile(e.dataTransfer.files[0]);
        });
    }

    if (malwareFileInput) {
        malwareFileInput.addEventListener("change", (e) => {
            if (e.target.files.length > 0) setMalwareFile(e.target.files[0]);
        });
    }

    if (malwareRemoveBtn) malwareRemoveBtn.addEventListener("click", clearMalwareFile);

    if (malwareScanBtn) {
        malwareScanBtn.addEventListener("click", async () => {
            if (!malwareSelectedFile) {
                showToast("error", "No File", "Please upload a file to analyze.");
                return;
            }
            if (state.scanning) {
                showToast("warning", "Scan in Progress", "Wait for the current scan to finish.");
                return;
            }

            state.scanning = true;
            malwareScanBtn.disabled = true;
            malwareScanBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Analyzing...';

            addToFeed("info", `Malware analysis started on ${malwareSelectedFile.name}`);

            try {
                const results = await MalwareAnalyzer.analyzeFile(
                    malwareSelectedFile,
                    $("#malwareOutput"),
                    $("#malwareProgress"),
                    $("#malwareFill"),
                    $("#malwareProgressText"),
                    $("#malwareVerdict")
                );

                state.scanData.malware = results;
                state.stats.scans++;
                if (results.riskScore >= 35) state.stats.vulns += results.findings.length;
                if (results.verdict === "MALICIOUS") state.stats.critical++;
                updateStats();

                addToHistory("malware", `Malware Analysis: ${results.verdict}`, malwareSelectedFile.name);
                addToFeed(results.verdict === "CLEAN" ? "success" : "error",
                    `Malware analysis complete: ${results.verdict} (score: ${results.riskScore}/100) for ${malwareSelectedFile.name}`
                );
                showToast(
                    results.verdict === "CLEAN" ? "success" : results.verdict === "MALICIOUS" ? "error" : "warning",
                    `Verdict: ${results.verdict}`,
                    `Risk score: ${results.riskScore}/100 for ${malwareSelectedFile.name}`
                );

                if (typeof ScanStore !== "undefined") ScanStore.saveScanResult("malware", results);
            } catch (err) {
                addToFeed("error", `Malware analysis failed: ${err.message}`);
                showToast("error", "Analysis Error", err.message);
            }

            state.scanning = false;
            malwareScanBtn.disabled = false;
            malwareScanBtn.innerHTML = '<i class="fas fa-microscope"></i> Analyze File';
        });
    }

    if (malwareClearBtn) {
        malwareClearBtn.addEventListener("click", () => {
            clearOutput("malwareOutput", "malwareProgress");
            const verdict = $("#malwareVerdict");
            if (verdict) verdict.innerHTML = "";
        });
    }
    if (malwareCopyBtn) malwareCopyBtn.addEventListener("click", () => copyOutput("malwareOutput"));

    // ========== REPORT GENERATOR ==========
    const genHtmlBtn = $("#genHtmlBtn");

    function getReportConfig() {
        return {
            title: $("#reportTitle").value || "NexPent VAPT Assessment Report",
            client: $("#reportClient").value || "",
            assessor: $("#reportAssessor").value || "NexPent Operator",
            sections: {
                sqli: $("#repSqli")?.checked || false,
                xss: $("#repXss")?.checked || false,
                bf: $("#repBf")?.checked || false,
                code: $("#repCode")?.checked || false,
                sub: $("#repSub")?.checked || false,
                port: $("#repPort")?.checked || false,
                nmap: $("#repNmap")?.checked || false,
                malware: $("#repMalware")?.checked || false,
                cve: $("#repCve")?.checked || false,
            },
        };
    }

    if (genHtmlBtn) {
        genHtmlBtn.addEventListener("click", () => {
            const config = getReportConfig();
            const html = ReportModule.generateHTMLReport(config, state.scanData);
            const preview = $("#reportPreview");
            if (preview) preview.innerHTML = html;

            state.stats.reports++;
            updateStats();

            addToFeed("success", "HTML report generated");
            showToast("success", "Report Generated", "HTML report is ready in the preview pane.");
        });
    }

    // ========== OWASP TOP 10 ==========
    const owaspSearch = $("#owaspSearch");
    const owaspGrid = $("#owaspGrid");

    if (owaspSearch && owaspGrid) {
        const owaspCards = owaspGrid.querySelectorAll(".owasp-card");

        // Search filter
        owaspSearch.addEventListener("input", () => {
            filterOwaspCards();
        });

        // Severity filter buttons
        $$(".owasp-filter-btn").forEach(btn => {
            btn.addEventListener("click", () => {
                $$(".owasp-filter-btn").forEach(b => b.classList.remove("active"));
                btn.classList.add("active");
                filterOwaspCards();
            });
        });

        function filterOwaspCards() {
            const query = owaspSearch.value.toLowerCase().trim();
            const activeFilter = $(".owasp-filter-btn.active")?.dataset.filter || "all";

            owaspCards.forEach(card => {
                const title = card.querySelector("h3")?.textContent.toLowerCase() || "";
                const desc = card.querySelector(".owasp-card-desc")?.textContent.toLowerCase() || "";
                const keywords = (card.dataset.keywords || "").toLowerCase();
                const severity = card.dataset.severity || "";

                const matchesSearch = !query || title.includes(query) || desc.includes(query) || keywords.includes(query);
                const matchesFilter = activeFilter === "all" || severity === activeFilter;

                if (matchesSearch && matchesFilter) {
                    card.style.display = "";
                    card.style.animation = "fadeInUp 0.3s ease forwards";
                } else {
                    card.style.display = "none";
                }
            });
        }
    }

    // ── OWASP Scanner Controls ──
    const owaspScanBtn = $("#owaspScanBtn");
    const owaspClearBtn = $("#owaspClearBtn");
    const owaspTerminal = $("#owaspTerminal");
    const owaspProgress = $("#owaspProgress");
    const owaspProgressFill = $("#owaspProgressFill");
    const owaspProgressText = $("#owaspProgressText");
    const owaspResultsSummary = $("#owaspResultsSummary");
    const owaspResultsStats = $("#owaspResultsStats");
    const owaspResultsGrid = $("#owaspResultsGrid");
    let owaspScanRunning = false;

    if (owaspScanBtn) {
        owaspScanBtn.addEventListener("click", async () => {
            const targetUrl = $("#owaspTargetUrl")?.value.trim();
            if (!targetUrl) {
                showToast("error", "Missing Target", "Please enter a target URL to scan.");
                return;
            }
            if (owaspScanRunning) {
                showToast("warning", "Scan Active", "An OWASP scan is already in progress.");
                return;
            }

            // Validate URL format
            try {
                new URL(targetUrl);
            } catch {
                showToast("error", "Invalid URL", "Please enter a valid URL (e.g., https://example.com).");
                return;
            }

            owaspScanRunning = true;
            owaspScanBtn.disabled = true;
            owaspScanBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Scanning...';
            owaspTerminal.innerHTML = "";
            owaspProgress.style.display = "flex";
            owaspProgressFill.style.width = "0%";
            owaspProgressText.textContent = "0%";
            owaspResultsSummary.style.display = "none";

            addToFeed("info", `OWASP Top 10 scan started on ${targetUrl}`);

            try {
                await OwaspScannerModule.runOwaspScan(
                    targetUrl,
                    owaspTerminal,
                    owaspProgressFill,
                    owaspProgressText,
                    (results, stats) => {
                        renderOwaspResults(results, stats);
                    }
                );

                state.stats.scans++;
                updateStats();
                showToast("success", "Scan Complete", `OWASP Top 10 scan finished on ${targetUrl}`);
                addToFeed("success", "OWASP Top 10 scan complete");

            } catch (err) {
                showToast("error", "Scan Error", err.message);
                addToFeed("error", `OWASP scan error: ${err.message}`);
            } finally {
                owaspScanRunning = false;
                owaspScanBtn.disabled = false;
                owaspScanBtn.innerHTML = '<i class="fas fa-play"></i> Start Scan';
            }
        });
    }

    if (owaspClearBtn) {
        owaspClearBtn.addEventListener("click", () => {
            if (owaspTerminal) owaspTerminal.innerHTML = "";
            if (owaspResultsSummary) owaspResultsSummary.style.display = "none";
            if (owaspProgress) owaspProgress.style.display = "none";
            if (owaspProgressFill) owaspProgressFill.style.width = "0%";
            if (owaspProgressText) owaspProgressText.textContent = "0%";
            showToast("info", "Cleared", "OWASP scan output cleared.");
        });
    }

    function renderOwaspResults(results, stats) {
        if (!owaspResultsSummary || !owaspResultsStats || !owaspResultsGrid) return;

        owaspResultsSummary.style.display = "block";

        // ── Stat cards ──
        owaspResultsStats.innerHTML = `
            <div class="owasp-stat-card total">
                <div class="owasp-stat-value">${stats.total}</div>
                <div class="owasp-stat-label">Total Findings</div>
            </div>
            <div class="owasp-stat-card critical">
                <div class="owasp-stat-value">${stats.critical}</div>
                <div class="owasp-stat-label">Critical</div>
            </div>
            <div class="owasp-stat-card high">
                <div class="owasp-stat-value">${stats.high}</div>
                <div class="owasp-stat-label">High</div>
            </div>
            <div class="owasp-stat-card medium">
                <div class="owasp-stat-value">${stats.medium}</div>
                <div class="owasp-stat-label">Medium</div>
            </div>
            <div class="owasp-stat-card low">
                <div class="owasp-stat-value">${stats.low}</div>
                <div class="owasp-stat-label">Low</div>
            </div>
        `;

        // ── Category result cards ──
        let gridHtml = "";
        results.forEach(cat => {
            const hasFindings = cat.findings.length > 0;
            const statusClass = hasFindings ? "vulnerable" : "secure";
            const statusIcon = hasFindings ? "fa-triangle-exclamation" : "fa-check-circle";
            const statusText = hasFindings ? `${cat.findings.length} issue(s)` : "Passed";

            let findingsHtml = "";
            cat.findings.forEach(f => {
                const sevClass = f.severity === "critical" ? "critical" : f.severity === "high" ? "high" : f.severity === "medium" ? "medium" : "low";
                findingsHtml += `
                    <div class="owasp-finding-item">
                        <div class="owasp-finding-header">
                            <span class="owasp-finding-name">${f.name}</span>
                            <span class="owasp-severity ${sevClass}">${f.severity.toUpperCase()}</span>
                        </div>
                        <div class="owasp-finding-evidence"><i class="fas fa-magnifying-glass"></i> ${f.evidence}</div>
                        <div class="owasp-finding-fix"><i class="fas fa-wrench"></i> ${f.remediation}</div>
                    </div>
                `;
            });

            gridHtml += `
                <div class="owasp-result-card ${statusClass}">
                    <div class="owasp-result-card-header">
                        <div class="owasp-result-id">${cat.id}</div>
                        <div class="owasp-result-info">
                            <h5><i class="fas ${cat.icon}"></i> ${cat.name}</h5>
                            <span class="owasp-result-status ${statusClass}">
                                <i class="fas ${statusIcon}"></i> ${statusText}
                            </span>
                        </div>
                    </div>
                    ${findingsHtml ? `<div class="owasp-findings-list">${findingsHtml}</div>` : ""}
                </div>
            `;
        });

        owaspResultsGrid.innerHTML = gridHtml;
    }

    // ========== EXPORT DASHBOARD ==========
    const exportDashBtn = $("#exportDashBtn");
    if (exportDashBtn) {
        exportDashBtn.addEventListener("click", () => {
            const config = getReportConfig();
            const html = ReportModule.generateHTMLReport(config, state.scanData);

            const fullHtml = `<!DOCTYPE html><html><head><title>NexPent Report</title>
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
            <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
            <style>
                :root{--accent:#00f0ff;--accent2:#7c3aed;--red:#ef4444;--orange:#f97316;--yellow:#fbbf24;--green:#10b981;--bg:#060810;--bg2:#0f1524;--border:#1e293b;--text:#e2e8f0;--text2:#94a3b8;--muted:#64748b}
                *{box-sizing:border-box;margin:0;padding:0}
                body{font-family:'Inter',sans-serif;background:var(--bg);color:var(--text);padding:2rem;max-width:900px;margin:auto;line-height:1.7}
                .report-html{color:var(--text)}
                .report-cover{text-align:center;padding:1.5rem;margin-bottom:1rem;background:linear-gradient(135deg,rgba(0,240,255,0.04),rgba(124,58,237,0.04));border:1px solid rgba(0,240,255,0.1);border-radius:12px}
                .report-cover-brand{display:flex;align-items:center;justify-content:center;gap:0.5rem;margin-bottom:0.75rem}
                .report-logo-icon{font-size:1.5rem;color:var(--accent)}
                .report-logo-text{font-size:1.8rem;font-weight:800;background:linear-gradient(135deg,var(--accent),var(--accent2));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
                h1{font-size:1.3rem;color:var(--text);margin-bottom:0.25rem}
                .report-subtitle{color:var(--muted);font-size:0.8rem}
                h2{font-size:1.05rem;color:var(--text);margin-top:1.75rem;margin-bottom:0.75rem;display:flex;align-items:center;gap:0.5rem;padding-bottom:0.5rem;border-bottom:1px solid var(--border)}
                h2::before{content:'▶';color:var(--accent);font-size:0.7rem}
                h2 i{display:none}
                p{color:var(--text2);margin-bottom:0.75rem;font-size:0.82rem}
                .report-meta{background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:1rem 1.25rem;margin-bottom:1.25rem;display:grid;grid-template-columns:1fr 1fr;gap:0.6rem}
                .report-meta-item{font-size:0.8rem;color:var(--text2);display:flex;align-items:center;gap:0.5rem}
                .report-meta-item i{color:var(--accent);width:14px;text-align:center;font-size:0.7rem}
                .report-meta-item strong{color:var(--text)}
                .report-risk-card{display:flex;align-items:center;gap:1.5rem;padding:1.25rem 1.5rem;border-radius:8px;margin-bottom:1.5rem;border:1px solid}
                .risk-critical{background:rgba(239,68,68,0.06);border-color:rgba(239,68,68,0.2)}
                .risk-high{background:rgba(249,115,22,0.06);border-color:rgba(249,115,22,0.2)}
                .risk-medium{background:rgba(245,158,11,0.06);border-color:rgba(245,158,11,0.2)}
                .risk-low{background:rgba(16,185,129,0.06);border-color:rgba(16,185,129,0.2)}
                .report-risk-circle{display:flex;align-items:baseline;gap:2px}
                .report-risk-value{font-size:2.5rem;font-weight:800;line-height:1}
                .risk-critical .report-risk-value{color:var(--red)}.risk-high .report-risk-value{color:var(--orange)}.risk-medium .report-risk-value{color:var(--yellow)}.risk-low .report-risk-value{color:var(--green)}
                .report-risk-max{font-size:0.9rem;color:var(--muted);font-weight:600}
                .report-risk-label{font-size:1.1rem;font-weight:700;margin-bottom:0.4rem}
                .risk-critical .report-risk-label{color:var(--red)}.risk-high .report-risk-label{color:var(--orange)}.risk-medium .report-risk-label{color:var(--yellow)}.risk-low .report-risk-label{color:var(--green)}
                .report-risk-stats{display:flex;gap:1rem;font-size:0.75rem;color:var(--text2)}
                .report-risk-stats span{display:flex;align-items:center;gap:0.3rem}
                .report-risk-stats i{font-size:0.65rem;color:var(--muted)}
                .report-toc{background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:1rem 1.25rem;margin-bottom:1.5rem}
                .report-toc h2{margin-top:0!important;padding-bottom:0.4rem;font-size:0.9rem}
                .report-toc-items{display:flex;flex-direction:column;gap:0.3rem}
                .report-toc-item{display:flex;align-items:center;gap:0.6rem;padding:0.35rem 0.5rem;font-size:0.78rem;color:var(--text2);border-radius:4px}
                .toc-num{width:20px;height:20px;border-radius:50%;background:rgba(0,240,255,0.08);border:1px solid rgba(0,240,255,0.15);color:var(--accent);font-size:0.6rem;font-weight:700;display:flex;align-items:center;justify-content:center;flex-shrink:0}
                table{width:100%;border-collapse:collapse;margin:0.75rem 0;font-size:0.78rem}
                th,td{padding:0.5rem 0.75rem;text-align:left;border:1px solid var(--border)}
                th{background:var(--bg2);color:var(--accent);font-weight:600;font-size:0.7rem;text-transform:uppercase;letter-spacing:0.5px}
                td{color:var(--text2)}
                tr:nth-child(even) td{background:rgba(0,0,0,0.1)}
                td code{background:rgba(0,0,0,0.3);padding:0.1rem 0.35rem;border-radius:3px;font-family:'JetBrains Mono',monospace;font-size:0.72rem;color:var(--accent);word-break:break-all}
                .report-badge{display:inline-block;padding:0.15rem 0.5rem;border-radius:10px;font-size:0.65rem;font-weight:700;text-transform:uppercase;letter-spacing:0.3px}
                .badge-critical{background:rgba(239,68,68,0.12);color:var(--red)}
                .badge-high{background:rgba(249,115,22,0.12);color:var(--orange)}
                .badge-medium{background:rgba(245,158,11,0.12);color:var(--yellow)}
                .badge-low{background:rgba(16,185,129,0.12);color:var(--green)}
                .severity-text{font-weight:700}
                .severity-critical{color:var(--red)}.severity-high{color:var(--orange)}.severity-medium{color:var(--yellow)}.severity-low{color:var(--green)}
                .report-alert{display:flex;align-items:center;gap:0.5rem;padding:0.65rem 1rem;border-radius:6px;font-size:0.8rem;font-weight:600;margin:0.5rem 0}
                .alert-danger{background:rgba(239,68,68,0.08);border:1px solid rgba(239,68,68,0.15);color:var(--red)}
                .alert-success{background:rgba(16,185,129,0.08);border:1px solid rgba(16,185,129,0.15);color:var(--green)}
                .report-alert i{font-size:0.75rem}
                .report-footer{margin-top:2rem;padding-top:1rem;border-top:1px solid var(--border)}
                .report-footer-brand{display:flex;justify-content:space-between;align-items:center;margin-top:1rem;padding:0.75rem 1rem;background:var(--bg2);border-radius:6px;font-size:0.7rem;color:var(--muted)}
            </style></head><body>${html}</body></html>`;

            const blob = new Blob([fullHtml], { type: "text/html" });
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = `NexPent_Dashboard_Export_${Date.now()}.html`;
            a.click();
            URL.revokeObjectURL(url);

            showToast("success", "Exported", "Dashboard report exported as HTML.");
        });
    }

    // ========== UTILITY FUNCTIONS ==========
    function clearOutput(outputId, progressId) {
        const output = document.getElementById(outputId);
        if (output) {
            output.innerHTML = `<div class="terminal-line system"><span class="time">[SYS]</span><span class="msg">Output cleared. Ready for new scan.</span></div>`;
        }
        if (progressId) {
            const progress = document.getElementById(progressId);
            if (progress) progress.style.display = "none";
        }
    }

    function copyOutput(outputId) {
        const output = document.getElementById(outputId);
        if (!output) return;
        const text = output.innerText;
        navigator.clipboard.writeText(text).then(() => {
            showToast("success", "Copied", "Output copied to clipboard.");
        }).catch(() => {
            showToast("error", "Copy Failed", "Could not copy to clipboard.");
        });
    }

    // ========== THEME TOGGLE (visual only) ==========
    const themeToggle = $("#themeToggle");
    if (themeToggle) {
        themeToggle.addEventListener("click", () => {
            showToast("info", "Theme", "Dark mode is the default — and the only way for hackers 🖤");
        });
    }

    // ========== NOTIFICATION BELL ==========
    const notifBtn = $("#notifBtn");
    if (notifBtn) {
        notifBtn.addEventListener("click", () => {
            showToast("info", "Notifications", `${state.stats.scans} scans performed, ${state.stats.vulns} vulnerabilities found.`);
            const dot = notifBtn.querySelector(".notif-dot");
            if (dot) dot.style.display = "none";
        });
    }

    // ========== AI CHATBOT ==========
    const aiChatInput = $("#aiChatInput");
    const aiSendBtn = $("#aiSendBtn");
    const aiChatMessages = $("#aiChatMessages");
    const aiClearChatBtn = $("#aiClearChatBtn");
    const aiAnalyzeScanBtn = $("#aiAnalyzeScanBtn");

    function getCurrentTime() {
        return new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }

    function addUserMessage(text) {
        const msgDiv = document.createElement("div");
        msgDiv.className = "ai-message ai-user-message";
        msgDiv.innerHTML = `
            <div class="ai-avatar">
                <i class="fas fa-user-secret"></i>
            </div>
            <div class="ai-msg-content">
                <div class="ai-msg-header">
                    <span class="ai-msg-name">You</span>
                    <span class="ai-msg-time">${getCurrentTime()}</span>
                </div>
                <div class="ai-msg-body">
                    <p>${escapeHtmlChat(text)}</p>
                </div>
            </div>
        `;
        aiChatMessages.appendChild(msgDiv);
        aiChatMessages.scrollTop = aiChatMessages.scrollHeight;
    }

    function showTypingIndicator() {
        const typingDiv = document.createElement("div");
        typingDiv.className = "ai-message ai-bot-message ai-typing-msg";
        typingDiv.innerHTML = `
            <div class="ai-avatar">
                <i class="fas fa-robot"></i>
                <div class="ai-avatar-pulse"></div>
            </div>
            <div class="ai-msg-content">
                <div class="ai-msg-header">
                    <span class="ai-msg-name">NexPent AI</span>
                    <span class="ai-msg-time">typing...</span>
                </div>
                <div class="ai-msg-body">
                    <div class="ai-typing-indicator">
                        <div class="ai-typing-dot"></div>
                        <div class="ai-typing-dot"></div>
                        <div class="ai-typing-dot"></div>
                    </div>
                </div>
            </div>
        `;
        aiChatMessages.appendChild(typingDiv);
        aiChatMessages.scrollTop = aiChatMessages.scrollHeight;
        return typingDiv;
    }

    function addBotMessage(htmlContent) {
        const msgDiv = document.createElement("div");
        msgDiv.className = "ai-message ai-bot-message";
        msgDiv.innerHTML = `
            <div class="ai-avatar">
                <i class="fas fa-robot"></i>
                <div class="ai-avatar-pulse"></div>
            </div>
            <div class="ai-msg-content">
                <div class="ai-msg-header">
                    <span class="ai-msg-name">NexPent AI</span>
                    <span class="ai-msg-time">${getCurrentTime()}</span>
                </div>
                <div class="ai-msg-body">
                    ${htmlContent}
                </div>
            </div>
        `;
        aiChatMessages.appendChild(msgDiv);
        aiChatMessages.scrollTop = aiChatMessages.scrollHeight;
    }

    function escapeHtmlChat(text) {
        const div = document.createElement("div");
        div.textContent = text;
        return div.innerHTML;
    }

    function handleChatSend(query) {
        if (!query || !query.trim()) return;
        const text = query.trim();

        addUserMessage(text);

        // Clear input
        if (aiChatInput) aiChatInput.value = "";

        // Show typing indicator
        const typing = showTypingIndicator();

        // Simulate AI "thinking" delay for realism
        const delay = 600 + Math.random() * 800;
        setTimeout(() => {
            // Remove typing indicator
            if (typing && typing.parentElement) typing.remove();

            // Process and respond
            const response = AIChatbotModule.processQuery(text, state.scanData);
            addBotMessage(response);

            // Auto-expand first solution
            setTimeout(() => {
                const firstSolution = aiChatMessages.querySelector(".ai-message:last-child .ai-solution-item:first-child");
                if (firstSolution && !firstSolution.classList.contains("expanded")) {
                    firstSolution.classList.add("expanded");
                }
            }, 200);
        }, delay);
    }

    // Send button click
    if (aiSendBtn) {
        aiSendBtn.addEventListener("click", () => {
            handleChatSend(aiChatInput?.value);
        });
    }

    // Enter key to send
    if (aiChatInput) {
        aiChatInput.addEventListener("keydown", (e) => {
            if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                handleChatSend(aiChatInput.value);
            }
        });
    }

    // Quick suggestion buttons
    const suggestionBtns = $$("#aiSuggestions .ai-suggestion-btn");
    suggestionBtns.forEach(btn => {
        btn.addEventListener("click", () => {
            const query = btn.dataset.query;
            if (query) handleChatSend(query);
        });
    });

    // Analyze scans button
    if (aiAnalyzeScanBtn) {
        aiAnalyzeScanBtn.addEventListener("click", () => {
            navigateTo("aichat");
            setTimeout(() => {
                handleChatSend("Analyze my scan results");
            }, 300);
        });
    }

    // Clear chat
    if (aiClearChatBtn) {
        aiClearChatBtn.addEventListener("click", () => {
            if (aiChatMessages) {
                aiChatMessages.innerHTML = "";
                // Re-add welcome message
                const welcomeDiv = document.createElement("div");
                welcomeDiv.className = "ai-message ai-bot-message ai-welcome-msg";
                welcomeDiv.innerHTML = `
                    <div class="ai-avatar">
                        <i class="fas fa-robot"></i>
                        <div class="ai-avatar-pulse"></div>
                    </div>
                    <div class="ai-msg-content">
                        <div class="ai-msg-header">
                            <span class="ai-msg-name">NexPent AI</span>
                            <span class="ai-msg-time">Now</span>
                        </div>
                        <div class="ai-msg-body">
                            <p>Chat cleared! I'm ready for your next security question. 🛡️</p>
                        </div>
                    </div>
                `;
                aiChatMessages.appendChild(welcomeDiv);
            }
            showToast("info", "Chat Cleared", "AI chat history has been cleared.");
        });
    }

    // ========== INITIAL SETUP ==========
    // Restore persisted scan data from localStorage for this account
    if (typeof ScanStore !== "undefined") {
        ScanStore.restore(state, updateStats, renderHistory);
        addToFeed("system", `[ScanStore] ${state.history.length} scan(s) restored from account history.`);
    } else {
        updateStats();
        renderHistory();
    }

    // Entrance animation
    setTimeout(() => {
        addToFeed("success", "NexPent VAPT Toolkit initialized and ready.");
    }, 500);

    console.log(`
    ╔══════════════════════════════════════╗
    ║   ███╗   ██╗███████╗██╗  ██╗        ║
    ║   ████╗  ██║██╔════╝╚██╗██╔╝        ║
    ║   ██╔██╗ ██║█████╗   ╚███╔╝         ║
    ║   ██║╚██╗██║██╔══╝   ██╔██╗         ║
    ║   ██║ ╚████║███████╗██╔╝ ██╗        ║
    ║   ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝        ║
    ║   NexPent VAPT Toolkit v2.0          ║
    ║   Advanced Penetration Testing       ║
    ╚══════════════════════════════════════╝
    `);
})();
