/* ============================================
   NexPent — Report Generator Module (HTML + PDF)
   ============================================ */

const ReportModule = (() => {
    "use strict";

    // ========== HTML REPORT ==========
    function generateHTMLReport(config, scanData) {
        const { title, client, assessor, sections } = config;
        const date = new Date().toLocaleString();
        const totalVulns = getTotalVulns(scanData, sections);
        const criticalCount = getCriticalCount(scanData, sections);
        const highCount = getHighCount(scanData, sections);
        const riskScore = calculateRiskScore(totalVulns, criticalCount, highCount);

        let html = `<div class="report-html">`;

        // ── Report Header ──
        html += `
        <div class="report-cover">
            <div class="report-cover-brand">
                <i class="fas fa-shield-halved report-logo-icon"></i>
                <span class="report-logo-text">NexPent</span>
            </div>
            <h1>${escapeHtml(title)}</h1>
            <p class="report-subtitle">Vulnerability Assessment & Penetration Testing Report</p>
        </div>`;

        // ── Meta Info ──
        html += `
        <div class="report-meta">
            <div class="report-meta-item"><i class="fas fa-building"></i> <strong>Client:</strong> ${escapeHtml(client || "N/A")}</div>
            <div class="report-meta-item"><i class="fas fa-user-shield"></i> <strong>Assessor:</strong> ${escapeHtml(assessor)}</div>
            <div class="report-meta-item"><i class="fas fa-calendar"></i> <strong>Date:</strong> ${date}</div>
            <div class="report-meta-item"><i class="fas fa-fingerprint"></i> <strong>Tool:</strong> NexPent VAPT Toolkit v2.0</div>
        </div>`;

        // ── Risk Score Card ──
        const riskLevel = riskScore >= 80 ? "critical" : riskScore >= 60 ? "high" : riskScore >= 30 ? "medium" : "low";
        const riskLabel = riskScore >= 80 ? "Critical Risk" : riskScore >= 60 ? "High Risk" : riskScore >= 30 ? "Medium Risk" : "Low Risk";
        html += `
        <div class="report-risk-card risk-${riskLevel}">
            <div class="report-risk-score">
                <div class="report-risk-circle">
                    <span class="report-risk-value">${riskScore}</span>
                    <span class="report-risk-max">/100</span>
                </div>
            </div>
            <div class="report-risk-info">
                <div class="report-risk-label">${riskLabel}</div>
                <div class="report-risk-stats">
                    <span><i class="fas fa-triangle-exclamation"></i> ${totalVulns} Vulnerabilities</span>
                    <span><i class="fas fa-skull-crossbones"></i> ${criticalCount} Critical</span>
                    <span><i class="fas fa-fire"></i> ${highCount} High</span>
                </div>
            </div>
        </div>`;

        // ── Table of Contents ──
        html += `<div class="report-toc">
            <h2><i class="fas fa-list"></i> Table of Contents</h2>
            <div class="report-toc-items">
                <div class="report-toc-item"><span class="toc-num">1</span> Executive Summary</div>
                <div class="report-toc-item"><span class="toc-num">2</span> Overall Statistics</div>`;
        let tocNum = 3;
        if (sections.sqli && scanData.sqli) html += `<div class="report-toc-item"><span class="toc-num">${tocNum++}</span> SQL Injection Analysis</div>`;
        if (sections.xss && scanData.xss) html += `<div class="report-toc-item"><span class="toc-num">${tocNum++}</span> XSS Analysis</div>`;
        if (sections.bf && scanData.bf) html += `<div class="report-toc-item"><span class="toc-num">${tocNum++}</span> Brute-Force Analysis</div>`;
        if (sections.code && scanData.code) html += `<div class="report-toc-item"><span class="toc-num">${tocNum++}</span> Static Code Analysis</div>`;
        if (sections.sub && scanData.sub) html += `<div class="report-toc-item"><span class="toc-num">${tocNum++}</span> Subdomain Enumeration</div>`;
        if (sections.port && scanData.port) html += `<div class="report-toc-item"><span class="toc-num">${tocNum++}</span> Port Scan Results</div>`;
        if (sections.nmap && scanData.nmap) html += `<div class="report-toc-item"><span class="toc-num">${tocNum++}</span> Nmap Network Discovery</div>`;
        if (sections.malware && scanData.malware) html += `<div class="report-toc-item"><span class="toc-num">${tocNum++}</span> Malware Analysis Results</div>`;
        if (sections.cve && scanData.cve && scanData.cve.length > 0) html += `<div class="report-toc-item"><span class="toc-num">${tocNum++}</span> CVE Intelligence</div>`;
        html += `<div class="report-toc-item"><span class="toc-num">${tocNum++}</span> Recommendations</div>`;
        html += `<div class="report-toc-item"><span class="toc-num">${tocNum}</span> Disclaimer</div>`;
        html += `</div></div>`;

        // ── Executive Summary ──
        html += `<h2>Executive Summary</h2>`;
        html += `<p>This report presents the findings of an automated vulnerability assessment and penetration test conducted using <strong>NexPent VAPT Toolkit</strong>. The assessment covered multiple attack vectors including SQL injection, cross-site scripting, brute-force resistance, static code analysis, subdomain enumeration, port scanning, and CVE identification.</p>`;
        if (totalVulns > 0) {
            html += `<p>A total of <strong>${totalVulns} vulnerabilities</strong> were identified, of which <strong>${criticalCount}</strong> are rated as <span class="severity-text severity-critical">Critical</span> and <strong>${highCount}</strong> as <span class="severity-text severity-high">High</span>. Immediate remediation is recommended for all critical and high severity findings.</p>`;
        } else {
            html += `<p>No significant vulnerabilities were detected during this assessment. The target appears to have a solid security posture. Continued regular assessments are recommended.</p>`;
        }

        // ── Overall Stats Table ──
        html += `<h2>Overall Statistics</h2>`;
        html += `<table>
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>Total Scans Performed</td><td>${scanData.totalScans || 0}</td></tr>
            <tr><td>Total Vulnerabilities</td><td><span class="severity-text ${totalVulns > 0 ? 'severity-high' : 'severity-low'}">${totalVulns}</span></td></tr>
            <tr><td>Critical Issues</td><td><span class="severity-text ${criticalCount > 0 ? 'severity-critical' : 'severity-low'}">${criticalCount}</span></td></tr>
            <tr><td>High Issues</td><td><span class="severity-text ${highCount > 0 ? 'severity-high' : 'severity-low'}">${highCount}</span></td></tr>
            <tr><td>Nmap Discovery</td><td>${scanData.nmap?.openPorts?.length || 0} Open Ports</td></tr>
            <tr><td>Malware Verdict</td><td><span class="severity-text severity-${scanData.malware?.verdict === 'MALICIOUS' ? 'critical' : scanData.malware?.verdict === 'SUSPICIOUS' ? 'high' : 'low'}">${scanData.malware?.verdict || 'N/A'}</span></td></tr>
            <tr><td>Risk Score</td><td><span class="severity-text severity-${riskLevel}">${riskScore}/100 (${riskLabel})</span></td></tr>
            <tr><td>Assessment Date</td><td>${date}</td></tr>
        </table>`;

        // ── SQL Injection Results ──
        if (sections.sqli && scanData.sqli) {
            html += `<h2>SQL Injection Analysis</h2>`;
            html += `<p><strong>Target:</strong> ${escapeHtml(scanData.sqli.target || "N/A")} &nbsp;|&nbsp; <strong>Method:</strong> ${scanData.sqli.method || "GET"}</p>`;
            if (scanData.sqli.vulns && scanData.sqli.vulns.length > 0) {
                html += `<div class="report-alert alert-danger"><i class="fas fa-exclamation-triangle"></i> ${scanData.sqli.vulns.length} SQL injection vulnerabilities detected!</div>`;
                html += `<table>
                    <tr><th>Payload</th><th>Type</th><th>Severity</th><th>Evidence</th></tr>`;
                scanData.sqli.vulns.forEach((v) => {
                    html += `<tr><td><code>${escapeHtml(v.payload)}</code></td><td>${v.type}</td><td><span class="report-badge badge-${(v.severity || 'high').toLowerCase()}">${v.severity || 'High'}</span></td><td>${escapeHtml(v.evidence || '')}</td></tr>`;
                });
                html += `</table>`;
            } else {
                html += `<div class="report-alert alert-success"><i class="fas fa-check-circle"></i> No SQL injection vulnerabilities detected.</div>`;
            }
        }

        // ── XSS Results ──
        if (sections.xss && scanData.xss) {
            html += `<h2>Cross-Site Scripting (XSS) Analysis</h2>`;
            html += `<p><strong>Target:</strong> ${escapeHtml(scanData.xss.target || "N/A")} &nbsp;|&nbsp; <strong>Parameter:</strong> ${escapeHtml(scanData.xss.param || "N/A")}</p>`;
            if (scanData.xss.vulns && scanData.xss.vulns.length > 0) {
                html += `<div class="report-alert alert-danger"><i class="fas fa-exclamation-triangle"></i> ${scanData.xss.vulns.length} XSS vulnerabilities detected!</div>`;
                html += `<table>
                    <tr><th>Payload</th><th>Type</th><th>Severity</th><th>Context</th></tr>`;
                scanData.xss.vulns.forEach((v) => {
                    html += `<tr><td><code>${escapeHtml(v.payload)}</code></td><td>${v.type}</td><td><span class="report-badge badge-${(v.severity || 'high').toLowerCase()}">${v.severity || 'High'}</span></td><td>${escapeHtml(v.context || '')}</td></tr>`;
                });
                html += `</table>`;
            } else {
                html += `<div class="report-alert alert-success"><i class="fas fa-check-circle"></i> No XSS vulnerabilities detected.</div>`;
            }
        }

        // ── Brute Force Results ──
        if (sections.bf && scanData.bf) {
            html += `<h2>Brute-Force Resistance Analysis</h2>`;
            html += `<p><strong>Target:</strong> ${escapeHtml(scanData.bf.target || "N/A")}</p>`;
            html += `<table>
                <tr><th>Metric</th><th>Result</th></tr>
                <tr><td>Total Combinations Tested</td><td>${scanData.bf.totalAttempts || 0}</td></tr>
                <tr><td>Valid Credentials Found</td><td><span class="severity-text ${(scanData.bf.found?.length || 0) > 0 ? 'severity-critical' : 'severity-low'}">${scanData.bf.found?.length || 0}</span></td></tr>
                <tr><td>Account Lockout</td><td>${scanData.bf.noLockout ? '<span class="severity-text severity-high">❌ Not Detected</span>' : '<span class="severity-text severity-low">✓ Detected</span>'}</td></tr>
                <tr><td>Rate Limiting</td><td>${scanData.bf.rateLimited ? '<span class="severity-text severity-low">✓ Detected</span>' : '<span class="severity-text severity-high">❌ Not Detected</span>'}</td></tr>
            </table>`;
            if (scanData.bf.found && scanData.bf.found.length > 0) {
                html += `<div class="report-alert alert-danger"><i class="fas fa-exclamation-triangle"></i> Valid credentials discovered — immediate password reset required!</div>`;
                html += `<table><tr><th>Username</th><th>Password</th><th>Status</th></tr>`;
                scanData.bf.found.forEach((c) => {
                    html += `<tr><td><code>${escapeHtml(c.username)}</code></td><td><code>${escapeHtml(c.password)}</code></td><td><span class="report-badge badge-critical">Compromised</span></td></tr>`;
                });
                html += `</table>`;
            }
        }

        // ── Code Analysis Results ──
        if (sections.code && scanData.code) {
            html += `<h2>Static Code Analysis</h2>`;
            html += `<p><strong>Language:</strong> ${scanData.code.language || "N/A"} &nbsp;|&nbsp; <strong>Security Score:</strong> <span class="severity-text severity-${(scanData.code.score || 0) >= 70 ? 'low' : (scanData.code.score || 0) >= 40 ? 'medium' : 'critical'}">${scanData.code.score || "N/A"}/100</span></p>`;
            if (scanData.code.findings && scanData.code.findings.length > 0) {
                html += `<table>
                    <tr><th>ID</th><th>Severity</th><th>Issue</th><th>Line</th><th>CWE</th></tr>`;
                scanData.code.findings.forEach((f) => {
                    html += `<tr><td>${f.id}</td><td><span class="report-badge badge-${(f.severity || 'medium').toLowerCase()}">${f.severity}</span></td><td>${escapeHtml(f.title)}</td><td>${f.line}</td><td>${f.cwe}</td></tr>`;
                });
                html += `</table>`;
            } else {
                html += `<div class="report-alert alert-success"><i class="fas fa-check-circle"></i> No security issues detected in code.</div>`;
            }
        }

        // ── Subdomain Results ──
        if (sections.sub && scanData.sub) {
            html += `<h2>Subdomain Enumeration</h2>`;
            html += `<p><strong>Target Domain:</strong> ${escapeHtml(scanData.sub.domain || "N/A")} &nbsp;|&nbsp; <strong>Found:</strong> ${scanData.sub.subdomains?.length || 0} subdomains</p>`;
            if (scanData.sub.subdomains && scanData.sub.subdomains.length > 0) {
                html += `<table><tr><th>Subdomain</th><th>IP Address</th><th>Record Type</th><th>Status</th></tr>`;
                scanData.sub.subdomains.forEach((s) => {
                    html += `<tr><td>${escapeHtml(s.subdomain)}</td><td><code>${s.ip}</code></td><td>${s.recordType}</td><td>${s.status}</td></tr>`;
                });
                html += `</table>`;
            }
        }

        // ── Port Scan Results ──
        if (sections.port && scanData.port) {
            html += `<h2>Port Scan Results</h2>`;
            html += `<p><strong>Target:</strong> ${escapeHtml(scanData.port.host || "N/A")} &nbsp;|&nbsp; <strong>Range:</strong> ${scanData.port.startPort}-${scanData.port.endPort}</p>`;
            if (scanData.port.openPorts && scanData.port.openPorts.length > 0) {
                html += `<table><tr><th>Port</th><th>Service</th><th>Version</th><th>Risk Level</th></tr>`;
                scanData.port.openPorts.forEach((p) => {
                    html += `<tr><td>${p.port}/tcp</td><td>${p.service}</td><td>${p.version}</td><td><span class="report-badge badge-${(p.risk || 'low').toLowerCase()}">${(p.risk || 'low').toUpperCase()}</span></td></tr>`;
                });
                html += `</table>`;
            } else {
                html += `<div class="report-alert alert-success"><i class="fas fa-check-circle"></i> No open ports found in the scanned range.</div>`;
            }
        }

        // ── Nmap Results ──
        if (sections.nmap && scanData.nmap) {
            html += `<h2>Nmap Network Discovery</h2>`;
            html += `<p><strong>Target:</strong> ${escapeHtml(scanData.nmap.target || "N/A")} &nbsp;|&nbsp; <strong>Scan Type:</strong> ${scanData.nmap.scanType || "SYN Scan"} &nbsp;|&nbsp; <strong>Timing:</strong> ${scanData.nmap.timing || "Normal"}</p>`;
            if (scanData.nmap.os) {
                html += `<p><strong>OS Detection:</strong> ${scanData.nmap.os.os} (${scanData.nmap.os.accuracy}% confidence)</p>`;
            }
            if (scanData.nmap.openPorts && scanData.nmap.openPorts.length > 0) {
                html += `<table><tr><th>Port</th><th>Service</th><th>Version</th><th>Risk Level</th></tr>`;
                scanData.nmap.openPorts.forEach((p) => {
                    html += `<tr><td>${p.port}/tcp</td><td>${p.service}</td><td>${p.version}</td><td><span class="report-badge badge-${(p.risk || 'low').toLowerCase()}">${(p.risk || 'low').toUpperCase()}</span></td></tr>`;
                });
                html += `</table>`;
            }
            if (scanData.nmap.vulns && scanData.nmap.vulns.length > 0) {
                html += `<div class="report-alert alert-danger"><i class="fas fa-exclamation-triangle"></i> ${scanData.nmap.vulns.length} high-risk services detected by Nmap!</div>`;
            }
        }

        // ── Malware Results ──
        if (sections.malware && scanData.malware) {
            html += `<h2>Malware Analysis Results</h2>`;
            html += `<p><strong>File Name:</strong> ${escapeHtml(scanData.malware.fileName || "N/A")} &nbsp;|&nbsp; <strong>Verdict:</strong> <span class="severity-text severity-${scanData.malware.verdict === 'MALICIOUS' ? 'critical' : scanData.malware.verdict === 'SUSPICIOUS' ? 'high' : 'low'}">${scanData.malware.verdict}</span></p>`;
            html += `<table>
                <tr><th>Metric</th><th>Value</th></tr>
                <tr><td>Risk Score</td><td>${scanData.malware.riskScore}/100</td></tr>
                <tr><td>Shannon Entropy</td><td>${scanData.malware.entropy?.toFixed(4) || 0}</td></tr>
                <tr><td>Matched Signatures</td><td>${scanData.malware.sigMatch ? `<span class="severity-text severity-critical">${scanData.malware.sigMatch}</span>` : 'None'}</td></tr>
                <tr><td>IOCs Found</td><td>${(scanData.malware.urls || 0) + (scanData.malware.ips || 0)}</td></tr>
            </table>`;

            if (scanData.malware.findings && scanData.malware.findings.length > 0) {
                html += `<table><tr><th>Pattern Found</th><th>Severity</th><th>Category</th></tr>`;
                scanData.malware.findings.forEach((f) => {
                    html += `<tr><td>${f.name}</td><td><span class="report-badge badge-${(f.severity || 'low').toLowerCase()}">${f.severity.toUpperCase()}</span></td><td>${f.category}</td></tr>`;
                });
                html += `</table>`;
            }
        }

        // ── CVE Results ──
        if (sections.cve && scanData.cve && scanData.cve.length > 0) {
            html += `<h2>CVE Intelligence</h2>`;
            html += `<table><tr><th>CVE ID</th><th>Severity</th><th>CVSS Score</th><th>Product</th><th>Description</th></tr>`;
            scanData.cve.forEach((c) => {
                html += `<tr><td><code>${c.id}</code></td><td><span class="report-badge badge-${(c.severity || 'medium').toLowerCase()}">${(c.severity || 'N/A').toUpperCase()}</span></td><td>${c.score}</td><td>${escapeHtml(c.product)}</td><td>${escapeHtml(c.title)}</td></tr>`;
            });
            html += `</table>`;
        }

        // ── Recommendations ──
        html += `<h2>Recommendations</h2>`;
        const recs = generateRecommendations(scanData, sections);
        html += `<table><tr><th>#</th><th>Recommendation</th><th>Priority</th></tr>`;
        recs.forEach((r, i) => {
            html += `<tr><td>${i + 1}</td><td>${r.text}</td><td><span class="report-badge badge-${r.priority === 'CRITICAL' ? 'critical' : r.priority === 'HIGH' ? 'high' : r.priority === 'MEDIUM' ? 'medium' : 'low'}">${r.priority}</span></td></tr>`;
        });
        html += `</table>`;

        // ── Footer / Disclaimer ──
        html += `<div class="report-footer">
            <h2>Disclaimer</h2>
            <p>This report is generated by <strong>NexPent VAPT Toolkit</strong> for authorized security assessment purposes only. The findings should be validated by a qualified security professional. This tool simulates vulnerability detection patterns and should be used as a supplementary assessment aid.</p>
            <div class="report-footer-brand">
                <span>Generated by NexPent VAPT Toolkit v2.0</span>
                <span>${date}</span>
            </div>
        </div>`;

        html += `</div>`;
        return html;
    }

    // ========== UTILITY FUNCTIONS ==========

    function generateRecommendations(scanData, sections) {
        const recs = [];

        if (sections.sqli && scanData.sqli?.vulns?.length > 0) {
            recs.push({ text: "Implement parameterized queries and prepared statements for all database operations to eliminate SQL injection vulnerabilities.", priority: "CRITICAL" });
            recs.push({ text: "Apply strict input validation and output encoding on all user-supplied data.", priority: "HIGH" });
        }

        if (sections.xss && scanData.xss?.vulns?.length > 0) {
            recs.push({ text: "Implement Content Security Policy (CSP) headers to prevent execution of unauthorized scripts.", priority: "HIGH" });
            recs.push({ text: "Use DOM sanitization libraries (e.g., DOMPurify) for all dynamic content rendering.", priority: "HIGH" });
        }

        if (sections.bf && scanData.bf) {
            if (scanData.bf.noLockout) {
                recs.push({ text: "Implement progressive account lockout after 5 consecutive failed login attempts.", priority: "HIGH" });
            }
            if (!scanData.bf.rateLimited) {
                recs.push({ text: "Add rate limiting (e.g., 10 requests/minute) to authentication endpoints.", priority: "MEDIUM" });
            }
            if (scanData.bf.found?.length > 0) {
                recs.push({ text: "Enforce strong password policy: minimum 12 characters with uppercase, lowercase, numbers, and symbols. Reset all compromised credentials immediately.", priority: "CRITICAL" });
            }
        }

        if (sections.code && scanData.code?.findings?.length > 0) {
            recs.push({ text: "Address all critical and high severity code issues identified in static analysis immediately.", priority: "CRITICAL" });
            recs.push({ text: "Integrate SAST tools into CI/CD pipeline for continuous security code scanning.", priority: "MEDIUM" });
        }

        if (sections.sub && scanData.sub?.subdomains?.length > 0) {
            recs.push({ text: "Audit all discovered subdomains and remove DNS records for decommissioned services to prevent subdomain takeover.", priority: "MEDIUM" });
        }

        if (sections.port && scanData.port?.openPorts?.length > 0) {
            const highRisk = scanData.port.openPorts.filter((p) => p.risk === "critical" || p.risk === "high");
            if (highRisk.length > 0) {
                recs.push({ text: `Restrict access to ${highRisk.length} high-risk open services using firewall rules and network segmentation.`, priority: "HIGH" });
            }
            recs.push({ text: "Close all unnecessary open ports and disable unused network services.", priority: "MEDIUM" });
        }

        if (sections.cve && scanData.cve?.length > 0) {
            recs.push({ text: "Establish a formal patch management program. Apply critical CVE patches within 24-72 hours of disclosure.", priority: "HIGH" });
        }

        if (sections.nmap && scanData.nmap?.vulns?.length > 0) {
            recs.push({ text: `Address ${scanData.nmap.vulns.length} critical/high risk services discovered during Nmap network scanning.`, priority: "CRITICAL" });
        }

        if (sections.malware && scanData.malware) {
            if (scanData.malware.verdict === "MALICIOUS") {
                recs.push({ text: "Malicious file detected. Ensure the file is removed from all systems and conduct an incident response investigation.", priority: "CRITICAL" });
            } else if (scanData.malware.verdict === "SUSPICIOUS") {
                recs.push({ text: "Suspicious file detected. Perform dynamic analysis in a sandbox environments to confirm intent.", priority: "HIGH" });
            }
        }

        if (recs.length === 0) {
            recs.push({ text: "Continue regular security assessments and maintain current patch management practices.", priority: "LOW" });
        }

        return recs;
    }

    function getTotalVulns(scanData, sections) {
        let total = 0;
        if (sections.sqli && scanData.sqli) total += scanData.sqli.vulns?.length || 0;
        if (sections.xss && scanData.xss) total += scanData.xss.vulns?.length || 0;
        if (sections.bf && scanData.bf) total += scanData.bf.found?.length || 0;
        if (sections.code && scanData.code) total += scanData.code.findings?.length || 0;
        if (sections.nmap && scanData.nmap) total += (scanData.nmap.criticalCount || 0) + (scanData.nmap.highCount || 0);
        if (sections.malware && scanData.malware && scanData.malware.riskScore >= 35) total += scanData.malware.findings?.length || 0;
        if (sections.cve && scanData.cve) total += scanData.cve.length;
        return total;
    }

    function getCriticalCount(scanData, sections) {
        let count = 0;
        if (sections.sqli && scanData.sqli) count += scanData.sqli.vulns?.filter((v) => v.severity === "critical" || v.severity === "Critical").length || 0;
        if (sections.xss && scanData.xss) count += scanData.xss.vulns?.filter((v) => v.severity === "critical" || v.severity === "Critical").length || 0;
        if (sections.code && scanData.code) count += scanData.code.findings?.filter((f) => f.severity === "critical" || f.severity === "Critical").length || 0;
        if (sections.nmap && scanData.nmap) count += scanData.nmap.criticalCount || 0;
        if (sections.malware && scanData.malware && scanData.malware.verdict === "MALICIOUS") count += scanData.malware.findings?.filter(f => f.severity === "critical").length || 0;
        if (sections.cve && scanData.cve) count += scanData.cve.filter((c) => c.severity === "critical" || c.severity === "Critical").length || 0;
        return count;
    }

    function getHighCount(scanData, sections) {
        let count = 0;
        if (sections.sqli && scanData.sqli) count += scanData.sqli.vulns?.filter((v) => v.severity === "high" || v.severity === "High").length || 0;
        if (sections.xss && scanData.xss) count += scanData.xss.vulns?.filter((v) => v.severity === "high" || v.severity === "High").length || 0;
        if (sections.code && scanData.code) count += scanData.code.findings?.filter((f) => f.severity === "high" || f.severity === "High").length || 0;
        if (sections.nmap && scanData.nmap) count += scanData.nmap.highCount || 0;
        if (sections.malware && scanData.malware && scanData.malware.verdict !== "CLEAN") count += scanData.malware.findings?.filter(f => f.severity === "high").length || 0;
        if (sections.cve && scanData.cve) count += scanData.cve.filter((c) => c.severity === "high" || c.severity === "High").length || 0;
        return count;
    }

    function calculateRiskScore(totalVulns, critical, high) {
        let score = 0;
        score += critical * 20;
        score += high * 10;
        score += Math.max(0, totalVulns - critical - high) * 3;
        return Math.min(100, score);
    }

    function escapeHtml(str) {
        if (!str) return "";
        const div = document.createElement("div");
        div.textContent = str;
        return div.innerHTML;
    }

    return { generateHTMLReport };
})();
