/* ============================================
   NexPent — CVE Lookup Module
   REAL-TIME: Queries the NIST NVD API for
   real CVE data instead of a hardcoded DB.
   ============================================ */

const CVELookupModule = (() => {
    // Fallback hardcoded database for when API is unavailable
    const fallbackDatabase = [
        { id: "CVE-2024-3094", title: "XZ Utils Backdoor", desc: "Malicious code in xz upstream tarballs.", severity: "critical", score: 10.0, vendor: "Tukaani Project", product: "XZ Utils", published: "2024-03-29", cwe: "CWE-506" },
        { id: "CVE-2024-21762", title: "Fortinet FortiOS Out-of-Bound Write", desc: "Out-of-bounds write in FortiOS SSL VPN.", severity: "critical", score: 9.8, vendor: "Fortinet", product: "FortiOS", published: "2024-02-09", cwe: "CWE-787" },
        { id: "CVE-2024-6387", title: "OpenSSH regreSSHion RCE", desc: "Signal handler race condition in sshd.", severity: "critical", score: 8.1, vendor: "OpenBSD", product: "OpenSSH", published: "2024-07-01", cwe: "CWE-362" },
        { id: "CVE-2024-4577", title: "PHP CGI Argument Injection", desc: "PHP CGI argument injection on Windows.", severity: "critical", score: 9.8, vendor: "PHP Group", product: "PHP", published: "2024-06-09", cwe: "CWE-78" },
    ];

    /**
     * Search the NIST NVD API v2.0 for real CVE data.
     * Falls back to hardcoded DB if API is unavailable.
     */
    async function search(query, severityFilter, yearStart, yearEnd) {
        query = query.trim();

        // Try real NVD API first
        try {
            const results = await searchNVD(query, severityFilter, yearStart, yearEnd);
            if (results && results.length > 0) {
                return results;
            }
        } catch (err) {
            console.warn("[CVE] NVD API call failed, trying fallback:", err.message);
        }

        // Fallback to local DB
        return searchFallback(query, severityFilter, yearStart, yearEnd);
    }

    /**
     * Query the NIST National Vulnerability Database API v2.0
     */
    async function searchNVD(query, severityFilter, yearStart, yearEnd) {
        let apiUrl = "https://services.nvd.nist.gov/rest/json/cves/2.0?";
        const params = new URLSearchParams();

        // Determine if the query is a specific CVE ID
        if (/^CVE-\d{4}-\d+$/i.test(query)) {
            params.set("cveId", query.toUpperCase());
        } else {
            params.set("keywordSearch", query);
            params.set("keywordExactMatch", "");
        }

        // Date range filter
        if (yearStart) {
            params.set("pubStartDate", `${yearStart}-01-01T00:00:00.000`);
        }
        if (yearEnd) {
            params.set("pubEndDate", `${yearEnd}-12-31T23:59:59.999`);
        }

        // Severity filter via CVSS
        if (severityFilter && severityFilter !== "all") {
            const severityMap = {
                critical: "CRITICAL",
                high: "HIGH",
                medium: "MEDIUM",
                low: "LOW",
            };
            if (severityMap[severityFilter]) {
                params.set("cvssV3Severity", severityMap[severityFilter]);
            }
        }

        // Limit results
        params.set("resultsPerPage", "25");

        apiUrl += params.toString();

        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 15000);

        const resp = await fetch(apiUrl, {
            headers: { "Accept": "application/json" },
            signal: controller.signal,
        });
        clearTimeout(timer);

        if (!resp.ok) {
            throw new Error(`NVD API error: HTTP ${resp.status}`);
        }

        const data = await resp.json();

        if (!data.vulnerabilities || data.vulnerabilities.length === 0) {
            return [];
        }

        // Transform NVD API response to our format
        return data.vulnerabilities.map(item => {
            const cve = item.cve;
            const metrics = cve.metrics || {};

            // Get CVSS v3.1 score
            let score = 0;
            let severity = "medium";
            if (metrics.cvssMetricV31 && metrics.cvssMetricV31.length > 0) {
                score = metrics.cvssMetricV31[0].cvssData.baseScore || 0;
                severity = (metrics.cvssMetricV31[0].cvssData.baseSeverity || "MEDIUM").toLowerCase();
            } else if (metrics.cvssMetricV30 && metrics.cvssMetricV30.length > 0) {
                score = metrics.cvssMetricV30[0].cvssData.baseScore || 0;
                severity = (metrics.cvssMetricV30[0].cvssData.baseSeverity || "MEDIUM").toLowerCase();
            } else if (metrics.cvssMetricV2 && metrics.cvssMetricV2.length > 0) {
                score = metrics.cvssMetricV2[0].cvssData.baseScore || 0;
                severity = score >= 9.0 ? "critical" : score >= 7.0 ? "high" : score >= 4.0 ? "medium" : "low";
            }

            // Get description
            const descriptions = cve.descriptions || [];
            const enDesc = descriptions.find(d => d.lang === "en") || descriptions[0] || {};
            const desc = enDesc.value || "No description available.";

            // Get CWE
            const weaknesses = cve.weaknesses || [];
            let cweId = "N/A";
            if (weaknesses.length > 0 && weaknesses[0].description && weaknesses[0].description.length > 0) {
                cweId = weaknesses[0].description[0].value || "N/A";
            }

            // Get vendor/product from CPE configurations
            let vendor = "Unknown";
            let product = "Unknown";
            const configurations = cve.configurations || [];
            if (configurations.length > 0 && configurations[0].nodes && configurations[0].nodes.length > 0) {
                const cpeMatch = configurations[0].nodes[0].cpeMatch;
                if (cpeMatch && cpeMatch.length > 0) {
                    const cpe = cpeMatch[0].criteria || "";
                    const cpeParts = cpe.split(":");
                    if (cpeParts.length >= 5) {
                        vendor = cpeParts[3] || "Unknown";
                        product = cpeParts[4] || "Unknown";
                    }
                }
            }

            // Get published date
            const published = (cve.published || "").substring(0, 10);

            // Get references
            const references = (cve.references || []).map(r => r.url).slice(0, 3);

            return {
                id: cve.id,
                title: desc.substring(0, 80) + (desc.length > 80 ? "..." : ""),
                desc,
                severity,
                score,
                vendor: vendor.charAt(0).toUpperCase() + vendor.slice(1),
                product: product.charAt(0).toUpperCase() + product.slice(1),
                published,
                references,
                cwe: cweId,
                source: "NVD API",
            };
        });
    }

    /**
     * Fallback local search when API is unavailable
     */
    function searchFallback(query, severityFilter, yearStart, yearEnd) {
        query = query.toLowerCase().trim();

        return fallbackDatabase.filter((cve) => {
            const matchesQuery =
                cve.id.toLowerCase().includes(query) ||
                cve.title.toLowerCase().includes(query) ||
                cve.desc.toLowerCase().includes(query) ||
                cve.product.toLowerCase().includes(query) ||
                cve.vendor.toLowerCase().includes(query);

            if (!matchesQuery) return false;

            if (severityFilter !== "all" && cve.severity !== severityFilter) return false;

            const year = parseInt(cve.published.substring(0, 4));
            if (year < yearStart || year > yearEnd) return false;

            return true;
        }).map(cve => ({ ...cve, source: "Local DB (Offline)" }));
    }

    function renderResults(results, container) {
        container.innerHTML = "";

        if (results.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <i class="fas fa-search"></i>
                    <p>No CVEs found</p>
                    <span>Try a different search query or adjust filters</span>
                </div>
            `;
            return;
        }

        // Show data source badge
        const source = results[0]?.source || "Unknown";
        const sourceBadge = document.createElement("div");
        sourceBadge.style.cssText = "display:flex;align-items:center;gap:0.5rem;margin-bottom:1rem;padding:0.5rem 1rem;border-radius:8px;font-size:0.78rem;font-weight:600;background:rgba(0,240,255,0.06);border:1px solid rgba(0,240,255,0.15);color:#00f0ff;";
        sourceBadge.innerHTML = `<i class="fas ${source.includes("NVD") ? "fa-cloud" : "fa-database"}"></i> Data source: ${source} — ${results.length} result(s)`;
        container.appendChild(sourceBadge);

        results.forEach((cve) => {
            const card = document.createElement("div");
            card.className = "cve-card";
            card.innerHTML = `
                <div class="cve-card-header">
                    <span class="cve-id">${cve.id}</span>
                    <span class="cve-severity ${cve.severity}">${cve.severity.toUpperCase()} (${cve.score})</span>
                </div>
                <div style="font-weight:600;font-size:0.85rem;margin-bottom:0.4rem;color:var(--text-primary)">${cve.title}</div>
                <div class="cve-desc">${cve.desc}</div>
                <div class="cve-meta">
                    <span><i class="fas fa-building"></i> ${cve.vendor}</span>
                    <span><i class="fas fa-cube"></i> ${cve.product}</span>
                    <span><i class="fas fa-calendar"></i> ${cve.published}</span>
                    <span><i class="fas fa-link"></i> ${cve.cwe}</span>
                </div>
                ${cve.references && cve.references.length > 0 ? `
                <div style="margin-top:0.5rem;font-size:0.72rem;">
                    ${cve.references.map(r => `<a href="${r}" target="_blank" rel="noopener" style="color:#00f0ff;text-decoration:none;display:block;margin-top:0.2rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"><i class="fas fa-external-link-alt"></i> ${r}</a>`).join("")}
                </div>
                ` : ""}
            `;
            container.appendChild(card);
        });
    }

    return { search, renderResults, fallbackDatabase };
})();
