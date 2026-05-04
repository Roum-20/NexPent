/* ============================================
   NexPent — AI Security Chatbot Module
   Provides intelligent remediation advice for
   detected vulnerabilities and attacks.
   ============================================ */

const AIChatbotModule = (() => {
    "use strict";

    // ========== KNOWLEDGE BASE ==========
    const knowledgeBase = {
        // ---- SQL Injection ----
        sqli: {
            keywords: ["sql injection", "sqli", "sql inject", "sql attack", "database injection", "union select", "or 1=1", "drop table", "sql vulnerability"],
            title: "SQL Injection (SQLi)",
            severity: "Critical",
            icon: "fa-database",
            description: "SQL Injection is a code injection technique that exploits vulnerabilities in an application's database layer by inserting malicious SQL statements.",
            solutions: [
                {
                    title: "Use Parameterized Queries / Prepared Statements",
                    detail: "Never concatenate user input directly into SQL queries. Use parameterized queries or prepared statements that separate SQL logic from data.",
                    code: `// ❌ Vulnerable Code\nconst query = "SELECT * FROM users WHERE id = " + userId;\n\n// ✅ Secure Code (Node.js with mysql2)\nconst query = "SELECT * FROM users WHERE id = ?";\nconnection.execute(query, [userId]);`,
                    language: "javascript"
                },
                {
                    title: "Input Validation & Sanitization",
                    detail: "Validate all user inputs against expected formats. Use allowlists for acceptable values, and reject any input that doesn't match.",
                    code: `# Python Example\nimport re\ndef validate_id(user_id):\n    if not re.match(r'^[0-9]+$', user_id):\n        raise ValueError("Invalid ID format")\n    return int(user_id)`,
                    language: "python"
                },
                {
                    title: "Use ORM (Object-Relational Mapping)",
                    detail: "ORMs like Sequelize, SQLAlchemy, or Hibernate abstract database queries and automatically handle parameterization.",
                    code: `// Sequelize ORM Example\nconst user = await User.findOne({\n    where: { id: userId }\n});\n// Query is automatically parameterized`,
                    language: "javascript"
                },
                {
                    title: "Implement Web Application Firewall (WAF)",
                    detail: "Deploy a WAF like ModSecurity, AWS WAF, or Cloudflare WAF to detect and block SQL injection attempts at the network level."
                },
                {
                    title: "Principle of Least Privilege",
                    detail: "Database accounts used by the application should have the minimum necessary permissions. Never use root/admin credentials for application database connections."
                },
                {
                    title: "Error Handling",
                    detail: "Never expose database error messages to users. Use generic error pages and log detailed errors server-side only."
                }
            ],
            references: [
                { title: "OWASP SQL Injection Guide", url: "https://owasp.org/www-community/attacks/SQL_Injection" },
                { title: "CWE-89: SQL Injection", url: "https://cwe.mitre.org/data/definitions/89.html" },
                { title: "NIST SQL Injection Guidelines", url: "https://csrc.nist.gov/" }
            ]
        },

        // ---- Cross-Site Scripting (XSS) ----
        xss: {
            keywords: ["xss", "cross-site scripting", "cross site scripting", "script injection", "xss attack", "reflected xss", "stored xss", "dom xss", "dom-based xss"],
            title: "Cross-Site Scripting (XSS)",
            severity: "High",
            icon: "fa-code",
            description: "XSS attacks inject malicious scripts into web pages viewed by other users, enabling session hijacking, data theft, and defacement.",
            solutions: [
                {
                    title: "Output Encoding / Escaping",
                    detail: "Encode all user-supplied data before rendering it in HTML, JavaScript, CSS, or URL contexts. Use context-specific encoding.",
                    code: `// JavaScript - HTML Entity Encoding\nfunction escapeHTML(str) {\n    const div = document.createElement('div');\n    div.textContent = str;\n    return div.innerHTML;\n}\n\n// Use in templates\ndocument.getElementById('output').textContent = userInput;\n// NOT: .innerHTML = userInput;`,
                    language: "javascript"
                },
                {
                    title: "Content Security Policy (CSP)",
                    detail: "Implement a strict CSP header to control which scripts can execute on your pages, preventing inline script execution.",
                    code: `# Nginx CSP Header\nadd_header Content-Security-Policy\n    "default-src 'self';\n     script-src 'self' 'nonce-{random}';\n     style-src 'self' 'unsafe-inline';\n     img-src 'self' data:;\n     connect-src 'self' api.example.com;";`,
                    language: "nginx"
                },
                {
                    title: "Use Modern Frameworks",
                    detail: "Frameworks like React, Angular, and Vue.js automatically escape output by default. Avoid using dangerouslySetInnerHTML (React) or v-html (Vue) with user data."
                },
                {
                    title: "HTTPOnly & Secure Cookie Flags",
                    detail: "Set HttpOnly flag on session cookies to prevent JavaScript access, and Secure flag to ensure cookies are only sent over HTTPS.",
                    code: `// Express.js Cookie Settings\nres.cookie('session', token, {\n    httpOnly: true,\n    secure: true,\n    sameSite: 'Strict',\n    maxAge: 3600000\n});`,
                    language: "javascript"
                },
                {
                    title: "Input Validation",
                    detail: "Validate and sanitize all input on the server side. Use libraries like DOMPurify for client-side HTML sanitization when rendering user-generated HTML is necessary.",
                    code: `// Using DOMPurify\nimport DOMPurify from 'dompurify';\nconst clean = DOMPurify.sanitize(dirtyHTML);`,
                    language: "javascript"
                }
            ],
            references: [
                { title: "OWASP XSS Prevention Cheat Sheet", url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html" },
                { title: "CWE-79: Cross-site Scripting", url: "https://cwe.mitre.org/data/definitions/79.html" }
            ]
        },

        // ---- Brute Force ----
        bruteforce: {
            keywords: ["brute force", "brute-force", "credential stuffing", "password attack", "login attack", "dictionary attack", "password cracking", "login brute"],
            title: "Brute Force / Credential Stuffing",
            severity: "High",
            icon: "fa-key",
            description: "Brute force attacks systematically try all possible passwords or credential combinations to gain unauthorized access.",
            solutions: [
                {
                    title: "Account Lockout Policy",
                    detail: "Lock accounts after a number of failed login attempts (e.g., 5 attempts). Implement progressive delays or temporary lockouts rather than permanent ones.",
                    code: `// Express.js Rate Limiting with express-rate-limit\nconst rateLimit = require('express-rate-limit');\n\nconst loginLimiter = rateLimit({\n    windowMs: 15 * 60 * 1000, // 15 minutes\n    max: 5, // 5 attempts per window\n    message: 'Too many login attempts, please try again later',\n    standardHeaders: true,\n    legacyHeaders: false,\n});`,
                    language: "javascript"
                },
                {
                    title: "Multi-Factor Authentication (MFA)",
                    detail: "Require a second authentication factor (TOTP, SMS, hardware key) in addition to the password. This makes stolen credentials useless without the second factor."
                },
                {
                    title: "CAPTCHA Implementation",
                    detail: "Add CAPTCHA challenges after failed login attempts to prevent automated attacks. Use Google reCAPTCHA v3 for invisible protection.",
                    code: `<!-- Google reCAPTCHA v3 -->\n<script src="https://www.google.com/recaptcha/api.js?render=SITE_KEY"></script>\n<script>\ngrecaptcha.ready(function() {\n    grecaptcha.execute('SITE_KEY', {action: 'login'})\n        .then(function(token) {\n            // Send token to server for verification\n        });\n});\n</script>`,
                    language: "html"
                },
                {
                    title: "Strong Password Policies",
                    detail: "Enforce minimum password length (12+ characters), complexity requirements, and check against breached password databases (Have I Been Pwned API)."
                },
                {
                    title: "Monitor & Alert",
                    detail: "Implement logging and alerting for multiple failed login attempts. Use SIEM tools to detect brute force patterns across the application."
                }
            ],
            references: [
                { title: "OWASP Brute Force Attack", url: "https://owasp.org/www-community/attacks/Brute_force_attack" },
                { title: "NIST Password Guidelines", url: "https://pages.nist.gov/800-63-3/sp800-63b.html" }
            ]
        },

        // ---- Code Vulnerabilities ----
        codevuln: {
            keywords: ["code vulnerability", "insecure code", "code scan", "sast", "static analysis", "code security", "vulnerable code", "hardcoded", "hardcoded password", "eval(", "unsafe function"],
            title: "Insecure Code Patterns",
            severity: "Medium–Critical",
            icon: "fa-file-code",
            description: "Insecure code patterns include hardcoded credentials, use of dangerous functions (eval), missing input validation, and improper error handling.",
            solutions: [
                {
                    title: "Eliminate Hardcoded Secrets",
                    detail: "Never hardcode passwords, API keys, or tokens in source code. Use environment variables or secret management tools like HashiCorp Vault, AWS Secrets Manager.",
                    code: `# ❌ Bad\nDB_PASSWORD = "super_secret_123"\n\n# ✅ Good\nimport os\nDB_PASSWORD = os.environ.get('DB_PASSWORD')\n\n# Or use python-dotenv\nfrom dotenv import load_dotenv\nload_dotenv()\nDB_PASSWORD = os.getenv('DB_PASSWORD')`,
                    language: "python"
                },
                {
                    title: "Avoid Dangerous Functions",
                    detail: "Never use eval(), exec(), system(), or similar functions with user input. These allow arbitrary code execution.",
                    code: `// ❌ Dangerous\neval(userInput);\n\n// ✅ Safe Alternatives\n// Use JSON.parse() for JSON data\nconst data = JSON.parse(userInput);\n\n// Use specific parsers for expressions\n// Use a sandboxed environment if dynamic execution is needed`,
                    language: "javascript"
                },
                {
                    title: "Implement Secure Coding Standards",
                    detail: "Follow OWASP Secure Coding Practices. Conduct regular code reviews and use SAST tools like SonarQube, Semgrep, or Snyk to automate vulnerability detection."
                },
                {
                    title: "Dependency Management",
                    detail: "Regularly audit and update third-party dependencies. Use tools like npm audit, Snyk, or Dependabot to identify vulnerable packages.",
                    code: `# Check for vulnerable packages\nnpm audit\nnpm audit fix\n\n# Or use Snyk\nsnyk test\nsnyk monitor`,
                    language: "bash"
                }
            ],
            references: [
                { title: "OWASP Secure Coding Practices", url: "https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/" },
                { title: "CWE Top 25 Dangerous Software Weaknesses", url: "https://cwe.mitre.org/top25/" }
            ]
        },

        // ---- Port Security ----
        portsecurity: {
            keywords: ["open port", "port scan", "port security", "exposed port", "unnecessary port", "service exposure", "port vulnerability", "port 22", "port 80", "port 443", "port 3306", "port 21", "firewall"],
            title: "Open Port / Service Exposure",
            severity: "Medium–High",
            icon: "fa-ethernet",
            description: "Unnecessary open ports expose services to potential attackers, increasing the attack surface and risk of exploitation.",
            solutions: [
                {
                    title: "Close Unnecessary Ports",
                    detail: "Audit all open ports and close any that are not required for operation. Disable unused services and daemons.",
                    code: `# Linux - Check open ports\nss -tulnp\nnetstat -tulnp\n\n# Disable unnecessary service\nsudo systemctl stop <service>\nsudo systemctl disable <service>\n\n# UFW Firewall\nsudo ufw default deny incoming\nsudo ufw allow 22/tcp   # SSH\nsudo ufw allow 443/tcp  # HTTPS\nsudo ufw enable`,
                    language: "bash"
                },
                {
                    title: "Implement Network Segmentation",
                    detail: "Separate critical services into different network zones (DMZ, internal, management). Use VLANs and firewall rules to restrict inter-zone traffic."
                },
                {
                    title: "Use Non-Standard Ports",
                    detail: "Change default ports for services like SSH (22→2222), RDP (3389→custom) to reduce automated scanning attacks (security through obscurity as an additional layer)."
                },
                {
                    title: "Regular Port Auditing",
                    detail: "Schedule regular port scans using tools like Nmap to detect unauthorized services. Automate this with CI/CD pipeline checks.",
                    code: `# Nmap scan examples\nnmap -sV -sC -O target.com    # Service & OS detection\nnmap -p- target.com            # Full port scan\nnmap --script vuln target.com  # Vulnerability scripts`,
                    language: "bash"
                },
                {
                    title: "Service Hardening",
                    detail: "For ports that must remain open, harden the services running on them. Keep services updated, use strong authentication, and apply principle of least privilege."
                }
            ],
            references: [
                { title: "NIST Port Security Guide", url: "https://csrc.nist.gov/" },
                { title: "CIS Benchmarks", url: "https://www.cisecurity.org/cis-benchmarks" }
            ]
        },

        // ---- Subdomain Takeover ----
        subdomain: {
            keywords: ["subdomain", "subdomain takeover", "dangling dns", "dns takeover", "subdomain enumeration", "subdomain security"],
            title: "Subdomain Security & Takeover",
            severity: "High",
            icon: "fa-globe",
            description: "Subdomain takeover occurs when a subdomain points to an external service (like S3, Heroku) that has been deprovisioned, allowing an attacker to claim it.",
            solutions: [
                {
                    title: "Audit DNS Records Regularly",
                    detail: "Review all DNS records periodically. Remove CNAME records pointing to decommissioned services. Use automated tools to detect dangling DNS entries."
                },
                {
                    title: "Implement DNS Monitoring",
                    detail: "Set up alerts for DNS changes. Use services like SecurityTrails, DNSspy, or custom scripts to monitor subdomain configurations.",
                    code: `# Check for dangling CNAME records\ndig subdomain.example.com CNAME\n\n# If CNAME points to unclaimed resource:\n# subdomain.example.com → old-app.herokuapp.com\n# → Remove the DNS record or reclaim the resource`,
                    language: "bash"
                },
                {
                    title: "Restrict Subdomain Creation",
                    detail: "Implement approval workflows for new subdomain creation. Maintain an inventory of all subdomains and their purposes."
                },
                {
                    title: "Use Wildcard SSL Certificates Carefully",
                    detail: "While convenient, wildcard certificates can be exploited if subdomains are compromised. Consider individual certificates for critical subdomains."
                }
            ],
            references: [
                { title: "OWASP Subdomain Takeover", url: "https://owasp.org/www-project-web-security-testing-guide/" },
                { title: "Can I Take Over XYZ?", url: "https://github.com/EdOverflow/can-i-take-over-xyz" }
            ]
        },

        // ---- CVE / Known Vulnerabilities ----
        cve: {
            keywords: ["cve", "common vulnerabilities", "known vulnerability", "exploit", "patch", "zero day", "0day", "vulnerability database", "nvd", "cve lookup"],
            title: "CVE / Known Vulnerabilities",
            severity: "Varies",
            icon: "fa-bug",
            description: "CVEs (Common Vulnerabilities and Exposures) are publicly disclosed security flaws. Unpatched CVEs are a primary attack vector.",
            solutions: [
                {
                    title: "Patch Management Program",
                    detail: "Establish a formal patch management process. Prioritize critical CVEs (CVSS 9.0+) and apply patches within defined SLAs (e.g., critical: 24-72 hours)."
                },
                {
                    title: "Vulnerability Scanning",
                    detail: "Regularly scan systems using vulnerability scanners like Nessus, OpenVAS, or Qualys. Integrate scanning into CI/CD pipelines for continuous assessment."
                },
                {
                    title: "Virtual Patching",
                    detail: "When immediate patching isn't possible, use WAF rules or IPS signatures to block known exploit patterns as a temporary mitigation."
                },
                {
                    title: "Software Inventory (SBOM)",
                    detail: "Maintain a Software Bill of Materials to quickly identify affected systems when new CVEs are disclosed. Use tools like Syft or CycloneDX.",
                    code: `# Generate SBOM with Syft\nsyft packages dir:./myapp -o cyclonedx-json > sbom.json\n\n# Scan SBOM for vulnerabilities with Grype\ngrype sbom:./sbom.json`,
                    language: "bash"
                },
                {
                    title: "Subscribe to Security Advisories",
                    detail: "Subscribe to vendor security advisories, NVD alerts, and CERT notifications. Set up automated alerts for CVEs affecting your technology stack."
                }
            ],
            references: [
                { title: "NIST NVD Database", url: "https://nvd.nist.gov/" },
                { title: "MITRE CVE", url: "https://cve.mitre.org/" },
                { title: "CISA Known Exploited Vulnerabilities", url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" }
            ]
        },

        // ---- DDoS / DoS ----
        ddos: {
            keywords: ["ddos", "dos", "denial of service", "distributed denial", "flood attack", "syn flood", "volumetric attack", "layer 7 attack", "application layer attack"],
            title: "DDoS / Denial of Service",
            severity: "High",
            icon: "fa-server",
            description: "DDoS attacks overwhelm systems with traffic to make services unavailable. They can target network, transport, or application layers.",
            solutions: [
                {
                    title: "CDN & DDoS Protection Services",
                    detail: "Use services like Cloudflare, AWS Shield, or Akamai to absorb and filter malicious traffic before it reaches your infrastructure."
                },
                {
                    title: "Rate Limiting & Traffic Shaping",
                    detail: "Implement rate limiting at the application and network level to prevent any single source from overwhelming your services.",
                    code: `# Nginx Rate Limiting\nlimit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;\n\nserver {\n    location /api/ {\n        limit_req zone=api burst=20 nodelay;\n        limit_req_status 429;\n    }\n}`,
                    language: "nginx"
                },
                {
                    title: "Auto-Scaling Infrastructure",
                    detail: "Design infrastructure to automatically scale horizontally during traffic spikes. Use load balancers with health checks to distribute traffic."
                },
                {
                    title: "Incident Response Plan",
                    detail: "Create and rehearse a DDoS incident response plan. Define escalation procedures, communication channels, and mitigation steps."
                }
            ],
            references: [
                { title: "CISA DDoS Guide", url: "https://www.cisa.gov/sites/default/files/publications/understanding-and-responding-to-ddos-attacks_508c.pdf" },
                { title: "OWASP DoS", url: "https://owasp.org/www-community/attacks/Denial_of_Service" }
            ]
        },

        // ---- CSRF ----
        csrf: {
            keywords: ["csrf", "cross-site request forgery", "request forgery", "session riding", "csrf token", "anti-csrf"],
            title: "Cross-Site Request Forgery (CSRF)",
            severity: "Medium–High",
            icon: "fa-shuffle",
            description: "CSRF tricks authenticated users into performing unintended actions on web applications where they're authenticated.",
            solutions: [
                {
                    title: "Anti-CSRF Tokens",
                    detail: "Generate unique, unpredictable tokens for each session/form and validate them on the server for every state-changing request.",
                    code: `// Express.js with csurf middleware\nconst csrf = require('csurf');\nconst csrfProtection = csrf({ cookie: true });\n\napp.get('/form', csrfProtection, (req, res) => {\n    res.render('form', { csrfToken: req.csrfToken() });\n});\n\napp.post('/process', csrfProtection, (req, res) => {\n    // Token is automatically validated\n    res.send('Form processed securely');\n});`,
                    language: "javascript"
                },
                {
                    title: "SameSite Cookie Attribute",
                    detail: "Set SameSite=Strict or SameSite=Lax on session cookies to prevent them from being sent in cross-origin requests.",
                    code: `Set-Cookie: session=abc123; SameSite=Strict; Secure; HttpOnly`,
                    language: "http"
                },
                {
                    title: "Verify Origin Headers",
                    detail: "Check the Origin and Referer headers on server-side to ensure requests originate from your application's domain."
                }
            ],
            references: [
                { title: "OWASP CSRF Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html" },
                { title: "CWE-352: CSRF", url: "https://cwe.mitre.org/data/definitions/352.html" }
            ]
        },

        // ---- IDOR ----
        idor: {
            keywords: ["idor", "insecure direct object reference", "object reference", "access control", "authorization bypass", "privilege escalation", "broken access"],
            title: "Insecure Direct Object Reference (IDOR)",
            severity: "High",
            icon: "fa-lock-open",
            description: "IDOR occurs when an application exposes internal object references (files, database records) without proper authorization checks.",
            solutions: [
                {
                    title: "Implement Authorization Checks",
                    detail: "Always verify that the authenticated user has permission to access the requested resource. Never rely on obscurity of IDs.",
                    code: `// Express.js Authorization Check\napp.get('/api/orders/:orderId', async (req, res) => {\n    const order = await Order.findById(req.params.orderId);\n    \n    // ✅ Verify ownership\n    if (order.userId !== req.user.id) {\n        return res.status(403).json({ error: 'Forbidden' });\n    }\n    \n    res.json(order);\n});`,
                    language: "javascript"
                },
                {
                    title: "Use Indirect References",
                    detail: "Map internal IDs to per-user or per-session references. Use UUIDs instead of sequential integers to make enumeration harder."
                },
                {
                    title: "Role-Based Access Control (RBAC)",
                    detail: "Implement a robust RBAC system. Define roles and permissions clearly and enforce them at every API endpoint and data access layer."
                }
            ],
            references: [
                { title: "OWASP IDOR", url: "https://owasp.org/www-project-web-security-testing-guide/" },
                { title: "CWE-639: IDOR", url: "https://cwe.mitre.org/data/definitions/639.html" }
            ]
        },

        // ---- SSRF ----
        ssrf: {
            keywords: ["ssrf", "server-side request forgery", "server side request", "internal network", "ssrf attack", "url fetching"],
            title: "Server-Side Request Forgery (SSRF)",
            severity: "High–Critical",
            icon: "fa-arrow-right-arrow-left",
            description: "SSRF allows attackers to make the server send requests to internal resources, potentially accessing internal services, cloud metadata, or other sensitive systems.",
            solutions: [
                {
                    title: "Allowlist Validation",
                    detail: "Only allow requests to known, trusted URLs/domains. Maintain a strict allowlist of permitted external services."
                },
                {
                    title: "Block Internal Network Requests",
                    detail: "Validate and block requests to private IP ranges (10.x.x.x, 172.16-31.x.x, 192.168.x.x), localhost, and cloud metadata endpoints.",
                    code: `# Block metadata endpoints (AWS)\n# In application code, reject URLs containing:\n# - 169.254.169.254 (AWS metadata)\n# - 127.0.0.1, localhost\n# - Private IP ranges\n# - Internal hostnames\n\nimport ipaddress\ndef is_safe_url(url):\n    hostname = urlparse(url).hostname\n    ip = socket.gethostbyname(hostname)\n    addr = ipaddress.ip_address(ip)\n    return addr.is_global  # Only allow public IPs`,
                    language: "python"
                },
                {
                    title: "Network-Level Controls",
                    detail: "Use firewall rules to restrict the server's outbound connections. Only allow necessary outbound traffic to specific destinations."
                }
            ],
            references: [
                { title: "OWASP SSRF", url: "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery" },
                { title: "CWE-918: SSRF", url: "https://cwe.mitre.org/data/definitions/918.html" }
            ]
        },

        // ---- General Security ----
        general: {
            keywords: ["security", "how to secure", "best practices", "hardening", "security assessment", "penetration test", "vulnerability", "protect", "defense", "mitigation", "remediation"],
            title: "General Security Best Practices",
            severity: "Informational",
            icon: "fa-shield-halved",
            description: "A comprehensive security posture requires multiple layers of defense, continuous monitoring, and regular assessments.",
            solutions: [
                {
                    title: "Defense in Depth",
                    detail: "Implement multiple security layers: WAF, IDS/IPS, network segmentation, application security, endpoint protection, and security monitoring."
                },
                {
                    title: "Regular Security Assessments",
                    detail: "Conduct regular VAPT assessments, code reviews, and red team exercises. Use NexPent toolkit for automated vulnerability scanning."
                },
                {
                    title: "Security Headers",
                    detail: "Implement security headers on all web applications to add extra layers of protection.",
                    code: `# Essential Security Headers\nX-Content-Type-Options: nosniff\nX-Frame-Options: DENY\nX-XSS-Protection: 1; mode=block\nStrict-Transport-Security: max-age=31536000; includeSubDomains\nContent-Security-Policy: default-src 'self'\nReferrer-Policy: strict-origin-when-cross-origin\nPermissions-Policy: camera=(), microphone=(), geolocation=()`,
                    language: "http"
                },
                {
                    title: "Incident Response Planning",
                    detail: "Develop and regularly test an incident response plan. Define roles, communication channels, and recovery procedures for security incidents."
                },
                {
                    title: "Security Awareness Training",
                    detail: "Train all team members on security best practices, phishing awareness, and secure coding. Regular training reduces human-factor vulnerabilities."
                }
            ],
            references: [
                { title: "OWASP Top 10", url: "https://owasp.org/www-project-top-ten/" },
                { title: "NIST Cybersecurity Framework", url: "https://www.nist.gov/cyberframework" },
                { title: "CIS Controls", url: "https://www.cisecurity.org/controls" }
            ]
        },

        // ---- Phishing ----
        phishing: {
            keywords: ["phishing", "phish", "social engineering", "email attack", "spear phishing", "whaling", "vishing"],
            title: "Phishing & Social Engineering",
            severity: "High",
            icon: "fa-fish",
            description: "Phishing attacks use deceptive communications to trick users into revealing credentials, clicking malicious links, or downloading malware.",
            solutions: [
                {
                    title: "Email Security Controls",
                    detail: "Implement SPF, DKIM, and DMARC email authentication to prevent email spoofing. Use email security gateways to filter phishing emails.",
                    code: `# DNS Records for Email Security\n# SPF Record\nv=spf1 include:_spf.google.com ~all\n\n# DKIM Record (selector._domainkey)\nv=DKIM1; k=rsa; p=<public_key>\n\n# DMARC Record\nv=DMARC1; p=reject; rua=mailto:dmarc@example.com`,
                    language: "dns"
                },
                {
                    title: "Security Awareness Training",
                    detail: "Conduct regular phishing simulations and security awareness training. Teach employees to identify suspicious emails, links, and requests."
                },
                {
                    title: "Multi-Factor Authentication",
                    detail: "Enforce MFA on all accounts to limit the impact of compromised credentials from phishing attacks."
                }
            ],
            references: [
                { title: "CISA Phishing Guide", url: "https://www.cisa.gov/secure-our-world/recognize-and-report-phishing" }
            ]
        },

        // ---- Ransomware ----
        ransomware: {
            keywords: ["ransomware", "ransom", "encrypt files", "malware", "crypto locker", "wannacry", "data encryption attack"],
            title: "Ransomware Protection",
            severity: "Critical",
            icon: "fa-virus",
            description: "Ransomware encrypts victim files and demands payment for decryption. It can cripple organizations and lead to significant data loss.",
            solutions: [
                {
                    title: "Regular Backups (3-2-1 Rule)",
                    detail: "Maintain at least 3 copies of data, on 2 different media types, with 1 copy stored offsite/offline. Test backup restoration regularly."
                },
                {
                    title: "Network Segmentation",
                    detail: "Segment networks to limit ransomware lateral movement. Isolate critical systems and implement strict firewall rules between segments."
                },
                {
                    title: "Endpoint Detection & Response (EDR)",
                    detail: "Deploy EDR solutions to detect and respond to ransomware behavior patterns. Use application whitelisting to prevent unauthorized executable execution."
                },
                {
                    title: "Patch & Update",
                    detail: "Keep all systems, software, and firmware updated. Many ransomware attacks exploit known vulnerabilities in unpatched systems."
                }
            ],
            references: [
                { title: "CISA Ransomware Guide", url: "https://www.cisa.gov/stopransomware" },
                { title: "No More Ransom Project", url: "https://www.nomoreransom.org/" }
            ]
        },

        // ---- Nmap / Network Reconnaissance ----
        nmap: {
            keywords: ["nmap", "network scan", "network reconnaissance", "port discovery", "service detection", "os detection", "nmap scan", "timing template", "syn scan", "stealth scan", "network mapping"],
            title: "Nmap / Network Reconnaissance",
            severity: "Medium–High",
            icon: "fa-network-wired",
            description: "Nmap scans reveal open ports, running services, OS fingerprints, and network topology. Attackers use this information to map attack surfaces and identify vulnerable services.",
            solutions: [
                {
                    title: "Close Unnecessary Ports & Services",
                    detail: "Review all open ports discovered by Nmap. Disable services that are not required for production. Each open port is a potential entry point. Use firewall rules to explicitly allow only required traffic.",
                    code: `# Linux: List listening ports\nss -tlnp\n\n# Disable unused service (e.g., FTP)\nsudo systemctl stop vsftpd\nsudo systemctl disable vsftpd\n\n# UFW: Allow only specific ports\nsudo ufw default deny incoming\nsudo ufw allow 22/tcp    # SSH\nsudo ufw allow 443/tcp   # HTTPS\nsudo ufw enable`,
                    language: "bash"
                },
                {
                    title: "Harden Detected Services",
                    detail: "For each service Nmap identified, apply hardening: update to latest version, enforce strong authentication, use TLS/SSL, and restrict access by IP where possible.",
                    code: `# SSH: Disable password auth, enforce key-based\n# /etc/ssh/sshd_config\nPasswordAuthentication no\nPubkeyAuthentication yes\nPermitRootLogin no\nMaxAuthTries 3\nAllowUsers deploy@192.168.1.0/24\n\n# Restart SSH\nsudo systemctl restart sshd`,
                    language: "bash"
                },
                {
                    title: "Implement Network Segmentation",
                    detail: "Separate sensitive services into different network zones. Use VLANs and firewall rules to prevent lateral movement if one service is compromised."
                },
                {
                    title: "Deploy IDS/IPS",
                    detail: "Install intrusion detection/prevention systems like Snort or Suricata to detect and block reconnaissance scanning attempts in real-time.",
                    code: `# Install Suricata on Ubuntu\nsudo apt install suricata\n\n# Start with default rules\nsudo suricata -c /etc/suricata/suricata.yaml -i eth0\n\n# Monitor alerts\ntail -f /var/log/suricata/fast.log`,
                    language: "bash"
                }
            ],
            references: [
                { title: "Nmap Official Documentation", url: "https://nmap.org/book/" },
                { title: "CIS Benchmarks for OS Hardening", url: "https://www.cisecurity.org/cis-benchmarks" },
                { title: "NIST Network Security Guide", url: "https://csrc.nist.gov/" }
            ]
        },

        // ---- Malware Analysis ----
        malware: {
            keywords: ["malware", "malware analysis", "virus", "trojan", "backdoor", "malicious file", "file analysis", "static analysis", "suspicious file", "entropy", "packed", "obfuscated", "malicious code", "worm", "spyware", "keylogger"],
            title: "Malware Analysis & Response",
            severity: "Critical",
            icon: "fa-biohazard",
            description: "Malware is software designed to damage, disrupt, or gain unauthorized access to systems. Static analysis examines file properties — hashes, entropy, strings, and patterns — without executing the file.",
            solutions: [
                {
                    title: "Quarantine & Isolate Immediately",
                    detail: "Move the suspicious file to a quarantined directory with no execute permissions. Disconnect the affected system from the network to prevent lateral spread or C2 communication.",
                    code: `# Linux: Quarantine a file\nmkdir -p /quarantine\nchmod 000 suspicious_file.exe\nmv suspicious_file.exe /quarantine/\nchattr +i /quarantine/suspicious_file.exe\n\n# Windows PowerShell:\nMove-Item .\\suspicious.exe C:\\Quarantine\\\nicacls C:\\Quarantine\\suspicious.exe /deny Everyone:F`,
                    language: "bash"
                },
                {
                    title: "Submit Hash to Threat Intelligence",
                    detail: "Check the file's SHA-256 hash against VirusTotal, MalwareBazaar, and other threat intelligence platforms for known detections and community analysis.",
                    code: `# Check hash on VirusTotal via API\ncurl -s "https://www.virustotal.com/api/v3/files/{SHA256_HASH}" \\\n  -H "x-apikey: YOUR_API_KEY" | jq '.data.attributes.last_analysis_stats'\n\n# Check MalwareBazaar\ncurl -s -X POST "https://mb-api.abuse.ch/api/v1/" \\\n  -d "query=get_info&hash={SHA256_HASH}" | jq .`,
                    language: "bash"
                },
                {
                    title: "Dynamic Analysis in Sandbox",
                    detail: "If static analysis is inconclusive, execute the file in an isolated sandbox environment (e.g., Cuckoo Sandbox, ANY.RUN, Joe Sandbox) to observe runtime behavior — file system changes, network connections, registry modifications.",
                    code: `# Submit to Cuckoo Sandbox\ncuckoo submit /quarantine/suspicious_file.exe\n\n# Or use ANY.RUN Cloud Sandbox\n# Upload at: https://any.run/\n# Monitors: Process tree, network traffic, file drops, registry changes`,
                    language: "bash"
                },
                {
                    title: "Implement Endpoint Detection & Response (EDR)",
                    detail: "Deploy EDR solutions like CrowdStrike Falcon, Microsoft Defender for Endpoint, or open-source OSSEC/Wazuh to continuously monitor endpoints for malicious behavior patterns.",
                    code: `# Install Wazuh agent (open-source EDR)\n# Ubuntu/Debian\ncurl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -\napt-get install wazuh-agent\n\n# Configure active response rules in ossec.conf\n<active-response>\n  <command>firewall-drop</command>\n  <location>local</location>\n  <rules_id>5712</rules_id>\n  <timeout>600</timeout>\n</active-response>`,
                    language: "bash"
                },
                {
                    title: "YARA Rules for Custom Detection",
                    detail: "Write YARA rules to detect the specific malware family or indicators found in your analysis. Deploy these rules across your organization for proactive detection.",
                    code: `rule Suspicious_File_Pattern {\n    meta:\n        description = "Detects files with high entropy and suspicious strings"\n        author = "NexPent"\n    strings:\n        $s1 = "eval(" ascii nocase\n        $s2 = "powershell" ascii nocase\n        $s3 = "cmd.exe" ascii nocase\n        $s4 = "reverse_shell" ascii nocase\n    condition:\n        2 of ($s*) and filesize < 5MB\n}`,
                    language: "yara"
                }
            ],
            references: [
                { title: "VirusTotal", url: "https://www.virustotal.com/" },
                { title: "MalwareBazaar", url: "https://bazaar.abuse.ch/" },
                { title: "YARA Rules Documentation", url: "https://yara.readthedocs.io/" },
                { title: "MITRE ATT&CK Framework", url: "https://attack.mitre.org/" }
            ]
        }
    };

    // ========== CONTEXTUAL GREETINGS ==========
    const greetings = [
        "Hello! I'm **NexPent AI**, your cybersecurity defense advisor. Ask me about any attack type and I'll provide detailed remediation solutions. 🛡️",
        "Welcome, operator. I'm here to help you understand and defend against security threats. What vulnerability would you like to analyze?",
        "NexPent AI Security Assistant ready. I can provide solutions for SQL injection, XSS, brute force, DDoS, and many more attack vectors. What's your concern?"
    ];

    const fallbackResponses = [
        "I couldn't find a specific match for your query, but I recommend checking the **OWASP Top 10** for the most common web application vulnerabilities. Can you provide more details about the attack type?",
        "That's an interesting query! While I don't have a specific playbook for that, I can help with SQL Injection, XSS, Brute Force, DDoS, CSRF, SSRF, IDOR, Phishing, Ransomware, and general security hardening. Which topic interests you?",
        "I'm not sure I understand the specific attack you're referring to. Try asking about common attack types like **SQL injection**, **XSS**, **brute force**, **port security**, or **CVE remediation**."
    ];

    // ========== QUICK SUGGESTION TOPICS ==========
    const quickSuggestions = [
        { label: "🔍 Analyze My Scans", query: "analyze my scan results" },
        { label: "SQL Injection Fix", query: "How to fix SQL injection?" },
        { label: "XSS Prevention", query: "How to prevent XSS attacks?" },
        { label: "Brute Force Defense", query: "How to stop brute force attacks?" },
        { label: "Port Security", query: "How to secure open ports?" },
        { label: "Nmap Defense", query: "How to defend against nmap findings?" },
        { label: "Malware Response", query: "How to respond to malware detection?" },
        { label: "DDoS Protection", query: "How to protect against DDoS?" },
        { label: "CSRF Prevention", query: "How to prevent CSRF?" },
        { label: "Ransomware Defense", query: "How to protect against ransomware?" },
    ];

    // ========== CORE FUNCTIONS ==========

    /**
     * Find the best matching knowledge base entry for a query
     */
    function findBestMatch(query) {
        const q = query.toLowerCase().trim();
        let bestMatch = null;
        let bestScore = 0;

        for (const [key, entry] of Object.entries(knowledgeBase)) {
            let score = 0;
            for (const keyword of entry.keywords) {
                if (q.includes(keyword)) {
                    score += keyword.split(" ").length * 2; // Multi-word matches score higher
                }
            }
            // Also check title
            if (q.includes(entry.title.toLowerCase())) {
                score += 5;
            }
            if (score > bestScore) {
                bestScore = score;
                bestMatch = entry;
            }
        }

        return bestScore > 0 ? bestMatch : null;
    }

    /**
     * Generate a formatted response from a knowledge base entry
     */
    function generateResponse(entry) {
        let html = `<div class="ai-response-card">`;

        // Header
        html += `<div class="ai-response-header">
            <div class="ai-response-title">
                <i class="fas ${entry.icon}"></i>
                <span>${entry.title}</span>
            </div>
            <span class="ai-severity-badge severity-${entry.severity.toLowerCase().replace(/[–\s]/g, '-')}">${entry.severity}</span>
        </div>`;

        // Description
        html += `<p class="ai-response-desc">${entry.description}</p>`;

        // Solutions
        html += `<div class="ai-solutions-section">
            <h4><i class="fas fa-wrench"></i> Remediation Solutions</h4>`;

        entry.solutions.forEach((sol, idx) => {
            html += `<div class="ai-solution-item">
                <div class="ai-solution-header" onclick="this.parentElement.classList.toggle('expanded')">
                    <span class="ai-solution-num">${idx + 1}</span>
                    <span class="ai-solution-title">${sol.title}</span>
                    <i class="fas fa-chevron-down ai-solution-chevron"></i>
                </div>
                <div class="ai-solution-body">
                    <p>${sol.detail}</p>`;

            if (sol.code) {
                html += `<div class="ai-code-block">
                    <div class="ai-code-header">
                        <span>${sol.language || "code"}</span>
                        <button class="ai-copy-code-btn" onclick="AIChatbotModule.copyCode(this)">
                            <i class="fas fa-copy"></i> Copy
                        </button>
                    </div>
                    <pre><code>${escapeHtml(sol.code)}</code></pre>
                </div>`;
            }

            html += `</div></div>`;
        });

        html += `</div>`;

        // References
        if (entry.references && entry.references.length > 0) {
            html += `<div class="ai-references-section">
                <h4><i class="fas fa-link"></i> References</h4>
                <div class="ai-ref-list">`;
            entry.references.forEach(ref => {
                html += `<a href="${ref.url}" target="_blank" rel="noopener noreferrer" class="ai-ref-link">
                    <i class="fas fa-external-link-alt"></i> ${ref.title}
                </a>`;
            });
            html += `</div></div>`;
        }

        html += `</div>`;
        return html;
    }

    /**
     * Generate SPECIFIC per-vulnerability fix code based on actual scan findings
     */
    function getSpecificFix(type, vuln) {
        if (type === "sqli") {
            const param = vuln.parameter || vuln.param || "user_input";
            const url = vuln.url || vuln.target || "/endpoint";
            return {
                title: `Fix SQLi on <code>${escapeHtml(url)}</code> (param: <code>${escapeHtml(param)}</code>)`,
                detail: `The parameter <strong>${escapeHtml(param)}</strong> at <strong>${escapeHtml(url)}</strong> is vulnerable to SQL injection${vuln.payload ? ' using payload: <code>' + escapeHtml(vuln.payload) + '</code>' : ''}. The server concatenates user input directly into SQL queries instead of using parameterized queries.`,
                code: `# VULNERABLE CODE (what was detected):\nquery = "SELECT * FROM users WHERE ${param} = '" + request.get("${param}") + "'"\n\n# FIXED CODE - Use parameterized queries:\n# Python (Flask + SQLAlchemy)\nfrom sqlalchemy import text\nresult = db.session.execute(\n    text("SELECT * FROM users WHERE ${param} = :val"),\n    {"val": request.args.get("${param}")}\n)\n\n# Node.js (Express + mysql2)\nconst [rows] = await pool.execute(\n    'SELECT * FROM users WHERE ${param} = ?',\n    [req.query.${param}]\n);\n\n# PHP (PDO)\n$stmt = $pdo->prepare("SELECT * FROM users WHERE ${param} = :val");\n$stmt->execute(['val' => $_GET['${param}']]);`,
                language: "python"
            };
        }
        if (type === "xss") {
            const param = vuln.parameter || vuln.param || "input";
            const url = vuln.url || vuln.target || "/page";
            const xssType = vuln.type || "reflected";
            return {
                title: `Fix ${xssType} XSS on <code>${escapeHtml(url)}</code> (param: <code>${escapeHtml(param)}</code>)`,
                detail: `The parameter <strong>${escapeHtml(param)}</strong> at <strong>${escapeHtml(url)}</strong> reflects user input without encoding${vuln.payload ? ', allowing injection of: <code>' + escapeHtml(vuln.payload) + '</code>' : ''}. This is a <strong>${xssType}</strong> XSS vulnerability.`,
                code: `// VULNERABLE CODE:\nelement.innerHTML = userInput;  // RAW HTML insertion!\n\n// FIX 1 - Use textContent instead of innerHTML:\nelement.textContent = userInput;\n\n// FIX 2 - Sanitize with DOMPurify:\nimport DOMPurify from 'dompurify';\nelement.innerHTML = DOMPurify.sanitize(userInput);\n\n// FIX 3 - Server-side encoding (Node.js):\nconst encode = (str) => str\n    .replace(/&/g, '&amp;').replace(/</g, '&lt;')\n    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');\nres.send('<p>' + encode(req.query.${param}) + '</p>');\n\n// FIX 4 - Add CSP header:\n// Content-Security-Policy: default-src 'self'; script-src 'self'`,
                language: "javascript"
            };
        }
        if (type === "bf") {
            const url = vuln.url || vuln.target || "/login";
            const user = vuln.username || vuln.user || "admin";
            const pass = vuln.password || vuln.pass || "password";
            return {
                title: `Weak credentials: <code>${escapeHtml(user)}:${escapeHtml(pass)}</code>`,
                detail: `The login at <strong>${escapeHtml(url)}</strong> accepted <strong>${escapeHtml(user)}:${escapeHtml(pass)}</strong>. This means weak password policy and no brute-force protection.`,
                code: `# IMMEDIATE ACTIONS:\n# 1. Force password reset for user "${user}"\n# 2. Implement rate limiting on ${url}\n\n# Node.js - Rate limiting:\nconst rateLimit = require('express-rate-limit');\nconst loginLimiter = rateLimit({\n    windowMs: 15 * 60 * 1000,  // 15 minutes\n    max: 5,                     // 5 attempts\n    message: 'Too many login attempts'\n});\napp.post('${url}', loginLimiter, handler);\n\n# Password policy enforcement:\nconst strongRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{12,}$/;\nif (!strongRegex.test(newPassword)) {\n    throw new Error('Weak password');\n}`,
                language: "javascript"
            };
        }
        if (type === "code") {
            const rule = vuln.rule || vuln.type || vuln.name || "Insecure Pattern";
            const line = vuln.line || vuln.lineNumber || "?";
            const file = vuln.file || vuln.fileName || "source file";
            const sev = vuln.severity || "medium";
            return {
                title: `Code issue: <code>${escapeHtml(rule)}</code> at line ${line}`,
                detail: `Found <strong>${escapeHtml(rule)}</strong> in <strong>${escapeHtml(file)}</strong> at line ${line} (severity: ${sev}). ${vuln.detail || vuln.description || ''}`,
                code: vuln.code || `// Review the flagged code at line ${line} in ${file}\n// Hardcoded secret -> Move to environment variable:\nconst secret = process.env.SECRET;  // NOT: const secret = "abc123"\n\n// eval() -> Replace with safe alternative:\nJSON.parse(data);  // NOT: eval(data)\n\n// Missing validation -> Add sanitization:\nconst clean = validator.escape(userInput);`,
                language: vuln.language || "javascript"
            };
        }
        if (type === "port" || type === "nmap") {
            const port = vuln.port || "?";
            const service = vuln.service || vuln.name || "unknown";
            const version = vuln.version || "";
            const risk = vuln.risk || "medium";
            const portFixes = {
                21: `# FTP (Port 21) - Replace with SFTP:\nsudo systemctl stop vsftpd && sudo systemctl disable vsftpd\n# Use SFTP instead (runs over SSH port 22):\nsftp user@host`,
                22: `# SSH (Port 22) - Harden:\n# /etc/ssh/sshd_config\nPort 2222\nPermitRootLogin no\nPasswordAuthentication no\nMaxAuthTries 3\n\nsudo systemctl restart sshd\nsudo apt install fail2ban`,
                23: `# Telnet (Port 23) - DISABLE IMMEDIATELY:\nsudo systemctl stop telnetd && sudo systemctl disable telnetd\n# Telnet is plaintext! Replace with SSH.`,
                80: `# HTTP (Port 80) - Redirect to HTTPS:\n# Nginx:\nserver {\n    listen 80;\n    return 301 https://$server_name$request_uri;\n}\n\n# Apache .htaccess:\nRewriteEngine On\nRewriteCond %{HTTPS} off\nRewriteRule ^(.*)$ https://%{HTTP_HOST}/$1 [R=301,L]`,
                3306: `# MySQL (Port 3306) - Restrict access:\n# /etc/mysql/my.cnf:\n[mysqld]\nbind-address = 127.0.0.1\n\nsudo ufw deny 3306\nmysql> DELETE FROM mysql.user WHERE User='';`,
                3389: `# RDP (Port 3389) - Secure it:\n# Enable NLA, require VPN for access\n# Never expose RDP directly to internet\nnetsh advfirewall firewall add rule name="RDP-VPN-Only" dir=in action=allow protocol=tcp localport=3389 remoteip=10.0.0.0/8`
            };
            return {
                title: `Port ${port}/tcp: <code>${escapeHtml(service)}</code> ${version ? '(' + escapeHtml(version) + ')' : ''} [${risk.toUpperCase()}]`,
                detail: `Port <strong>${port}</strong> is running <strong>${escapeHtml(service)}${version ? ' ' + escapeHtml(version) : ''}</strong>. Risk: <strong>${risk}</strong>.`,
                code: portFixes[port] || `# Port ${port} (${service}) - Hardening:\nsudo ufw deny ${port}/tcp        # Block if unneeded\n# If needed, restrict by IP:\nsudo ufw allow from 10.0.0.0/8 to any port ${port}`,
                language: "bash"
            };
        }
        if (type === "malware") {
            const pattern = vuln.name || vuln.pattern || "Suspicious Pattern";
            const sev = vuln.severity || "medium";
            const cat = vuln.category || "unknown";
            const count = vuln.count || 1;
            const catDesc = {
                "code-execution": "arbitrary code execution attacks",
                "obfuscation": "code obfuscation to evade detection",
                "data-theft": "data exfiltration and credential theft",
                "network": "unauthorized network communications",
                "persistence": "establishing persistent access",
                "evasion": "security evasion techniques",
                "ransomware": "ransomware and file encryption",
                "backdoor": "backdoor access and remote control",
                "lateral-movement": "lateral movement within the network",
                "injection": "code/command injection",
                "spyware": "spyware and surveillance",
                "payload": "malicious payload delivery"
            };
            const catFixes = {
                "code-execution": `# Remove code execution vectors:\n# Replace eval() with safe alternatives:\nJSON.parse(data);  // NOT: eval(data)\n# Block shell execution:\n# NEVER use: exec(), system(), shell_exec()\n# Use libraries with predefined commands`,
                "obfuscation": `# De-obfuscate and analyze:\n# Use CyberChef: https://gchq.github.io/CyberChef/\n\nimport base64\ndecoded = base64.b64decode(suspicious_string)\nprint(decoded)`,
                "persistence": `# Remove persistence mechanisms:\n# Windows:\nschtasks /query /fo LIST /v\nreg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n\n# Linux:\ncrontab -l\nls -la /etc/init.d/\nsystemctl list-unit-files --type=service`,
                "network": `# Block unauthorized network access:\nsudo ufw default deny outgoing\nsudo ufw allow out 443/tcp  # HTTPS only\n\n# Monitor connections:\nnetstat -tlnp | grep ESTABLISHED`,
                "backdoor": `# Detect and remove backdoors:\n# Check for reverse shells:\nnetstat -tlnp | grep -E '(4444|5555|1337|9999)'\n\n# Check for unauthorized SSH keys:\ncat ~/.ssh/authorized_keys\n\n# Scan with rkhunter:\nsudo rkhunter --check`
            };
            return {
                title: `Malware: <code>${escapeHtml(pattern)}</code> x${count} [${sev.toUpperCase()}]`,
                detail: `Found <strong>${count}</strong> occurrence(s) of <strong>${escapeHtml(pattern)}</strong> (category: <em>${cat}</em>). Associated with ${catDesc[cat] || 'malicious activity'}.`,
                code: catFixes[cat] || `# Investigate: ${pattern}\ngrep -rn "${pattern.replace(/[^a-zA-Z0-9 ]/g, '.')}" /path/to/codebase/\nps aux | grep -i "${pattern.split(' ')[0] || 'suspicious'}"`,
                language: "bash"
            };
        }
        return null;
    }

    /**
     * Generate response from scan context - SPECIFIC per-vulnerability solutions
     */
    function generateScanContextResponse(scanData) {
        const allFindings = [];

        if (scanData.sqli && scanData.sqli.vulns && scanData.sqli.vulns.length > 0) {
            scanData.sqli.vulns.forEach(v => allFindings.push({ type: "sqli", severity: "critical", entry: knowledgeBase.sqli, vuln: v }));
        }
        if (scanData.xss && scanData.xss.vulns && scanData.xss.vulns.length > 0) {
            scanData.xss.vulns.forEach(v => allFindings.push({ type: "xss", severity: "high", entry: knowledgeBase.xss, vuln: v }));
        }
        if (scanData.bf && scanData.bf.found && scanData.bf.found.length > 0) {
            scanData.bf.found.forEach(v => allFindings.push({ type: "bf", severity: "high", entry: knowledgeBase.bruteforce, vuln: v }));
        }
        if (scanData.code && scanData.code.findings && scanData.code.findings.length > 0) {
            scanData.code.findings.forEach(v => {
                const s = (v.severity || "medium").toLowerCase();
                allFindings.push({ type: "code", severity: s === "critical" ? "critical" : s === "high" ? "high" : "medium", entry: knowledgeBase.codevuln, vuln: v });
            });
        }
        if (scanData.port && scanData.port.openPorts && scanData.port.openPorts.length > 0) {
            scanData.port.openPorts.forEach(p => {
                const r = (p.risk || "medium").toLowerCase();
                if (r === "high" || r === "critical") allFindings.push({ type: "port", severity: r, entry: knowledgeBase.portsecurity, vuln: p });
            });
        }
        if (scanData.nmap && scanData.nmap.openPorts && scanData.nmap.openPorts.length > 0) {
            scanData.nmap.openPorts.forEach(p => {
                const r = (p.risk || "medium").toLowerCase();
                if (r === "high" || r === "critical") allFindings.push({ type: "nmap", severity: r, entry: knowledgeBase.nmap, vuln: p });
            });
        }
        if (scanData.malware && scanData.malware.findings && scanData.malware.findings.length > 0) {
            scanData.malware.findings.forEach(f => {
                allFindings.push({ type: "malware", severity: (f.severity || "medium").toLowerCase(), entry: knowledgeBase.malware, vuln: f });
            });
        }

        if (allFindings.length === 0) {
            return `<div class="ai-response-card">
                <div class="ai-response-header">
                    <div class="ai-response-title">
                        <i class="fas fa-check-circle" style="color:#34d399"></i>
                        <span>Scan Analysis &mdash; All Clear</span>
                    </div>
                    <span class="ai-severity-badge" style="background:rgba(52,211,153,0.15);color:#34d399">CLEAN</span>
                </div>
                <p class="ai-response-desc">No significant vulnerabilities detected in your recent scans. Your security posture looks good! Continue regular assessments to maintain this status.</p>
            </div>`;
        }

        const sevOrder = { critical: 0, high: 1, medium: 2, low: 3 };
        allFindings.sort((a, b) => (sevOrder[a.severity] || 3) - (sevOrder[b.severity] || 3));

        const critCount = allFindings.filter(f => f.severity === "critical").length;
        const highCount = allFindings.filter(f => f.severity === "high").length;
        const medCount = allFindings.filter(f => f.severity === "medium").length;

        let html = `<div class="ai-response-card">
            <div class="ai-response-header">
                <div class="ai-response-title">
                    <i class="fas fa-crosshairs"></i>
                    <span>Vulnerability-Specific Remediation Plan</span>
                </div>
                <span class="ai-severity-badge severity-critical">${allFindings.length} Findings</span>
            </div>
            <p class="ai-response-desc">
                I analyzed your scan results and found <strong>${allFindings.length} specific vulnerabilities</strong>
                ${critCount > 0 ? ` (<span style="color:#ef4444">${critCount} critical</span>)` : ''}
                ${highCount > 0 ? ` (<span style="color:#f97316">${highCount} high</span>)` : ''}
                ${medCount > 0 ? ` (<span style="color:#fbbf24">${medCount} medium</span>)` : ''}.
                Below is a <strong>targeted fix for each specific vulnerability</strong> with exact code to remediate the issue.
            </p>
            <div class="ai-solutions-section">
                <h4><i class="fas fa-screwdriver-wrench"></i> Per-Vulnerability Fixes (${allFindings.length})</h4>`;

        allFindings.forEach((finding, idx) => {
            const fix = getSpecificFix(finding.type, finding.vuln);
            if (!fix) return;
            const sevColor = finding.severity === "critical" ? "#ef4444" : finding.severity === "high" ? "#f97316" : "#fbbf24";

            html += `<div class="ai-solution-item">
                <div class="ai-solution-header" onclick="this.parentElement.classList.toggle('expanded')">
                    <span class="ai-solution-num" style="background:${sevColor}20;color:${sevColor}">${idx + 1}</span>
                    <i class="fas ${finding.entry.icon}" style="color:${sevColor};margin-right:6px"></i>
                    <span class="ai-solution-title">${fix.title} <span style="font-size:0.7em;color:${sevColor};margin-left:6px">[${finding.severity.toUpperCase()}]</span></span>
                    <i class="fas fa-chevron-down ai-solution-chevron"></i>
                </div>
                <div class="ai-solution-body">
                    <p>${fix.detail}</p>`;
            if (fix.code) {
                html += `<div class="ai-code-block">
                    <div class="ai-code-header">
                        <span>${fix.language || "code"}</span>
                        <button class="ai-copy-code-btn" onclick="AIChatbotModule.copyCode(this)">
                            <i class="fas fa-copy"></i> Copy
                        </button>
                    </div>
                    <pre><code>${escapeHtml(fix.code)}</code></pre>
                </div>`;
            }
            html += `</div></div>`;
        });

        html += `</div>`;

        // References
        const shown = new Set();
        const refs = [];
        allFindings.forEach(f => { if (!shown.has(f.type)) { shown.add(f.type); refs.push(f.entry); } });
        if (refs.length > 0) {
            html += `<div class="ai-references-section"><h4><i class="fas fa-link"></i> References</h4><div class="ai-ref-list">`;
            refs.forEach(e => (e.references || []).forEach(r => {
                html += `<a href="${r.url}" target="_blank" rel="noopener noreferrer" class="ai-ref-link"><i class="fas fa-external-link-alt"></i> ${r.title}</a>`;
            }));
            html += `</div></div>`;
        }

        html += `</div>`;
        return html;
    }

    /**
     * Process a user query and return response
     */
    function processQuery(query, scanData) {
        const q = query.toLowerCase().trim();

        // Check for scan analysis request
        if (q.includes("analyze scan") || q.includes("scan result") || q.includes("my scan") || q.includes("analyze result") || q.includes("what did") || q.includes("fix my scan") || q.includes("fix vulnerabilit") || q.includes("remediate") || q.includes("how to fix") && q.includes("scan") || q.includes("show fixes") || q.includes("fix findings")) {
            return generateScanContextResponse(scanData || {});
        }

        // Check for greeting
        if (q.match(/^(hi|hello|hey|sup|greetings|howdy|what's up|whats up)/)) {
            return `<p>${greetings[Math.floor(Math.random() * greetings.length)]}</p>`;
        }

        // Check for help
        if (q === "help" || q === "?" || q.includes("what can you do") || q.includes("how to use")) {
            return `<div class="ai-response-card">
                <div class="ai-response-header">
                    <div class="ai-response-title">
                        <i class="fas fa-circle-info"></i>
                        <span>How to Use NexPent AI</span>
                    </div>
                </div>
                <p class="ai-response-desc">I'm your cybersecurity defense advisor. I provide <strong>vulnerability-specific remediation</strong> with exact fix code. Here's what I cover:</p>
                <div class="ai-help-list">
                    <div class="ai-help-item"><i class="fas fa-database"></i> <strong>SQL Injection</strong> &mdash; Parameterized query fixes per endpoint</div>
                    <div class="ai-help-item"><i class="fas fa-code"></i> <strong>XSS</strong> &mdash; Context-specific encoding & CSP fixes</div>
                    <div class="ai-help-item"><i class="fas fa-key"></i> <strong>Brute Force</strong> &mdash; Rate limiting & credential hardening</div>
                    <div class="ai-help-item"><i class="fas fa-ethernet"></i> <strong>Port Security</strong> &mdash; Per-port hardening commands</div>
                    <div class="ai-help-item"><i class="fas fa-network-wired"></i> <strong>Nmap</strong> &mdash; Service-specific remediation</div>
                    <div class="ai-help-item"><i class="fas fa-biohazard"></i> <strong>Malware</strong> &mdash; Pattern-specific response & containment</div>
                    <div class="ai-help-item"><i class="fas fa-bug"></i> <strong>CVE</strong> &mdash; Patch management guidance</div>
                    <div class="ai-help-item"><i class="fas fa-server"></i> <strong>DDoS</strong> &mdash; CDN & rate limit configuration</div>
                    <div class="ai-help-item"><i class="fas fa-shuffle"></i> <strong>CSRF</strong> &mdash; Token implementation code</div>
                    <div class="ai-help-item"><i class="fas fa-lock-open"></i> <strong>IDOR</strong> &mdash; Authorization check patterns</div>
                    <div class="ai-help-item"><i class="fas fa-arrow-right-arrow-left"></i> <strong>SSRF</strong> &mdash; Allowlist & network controls</div>
                    <div class="ai-help-item"><i class="fas fa-fish"></i> <strong>Phishing</strong> &mdash; Email security & awareness</div>
                    <div class="ai-help-item"><i class="fas fa-virus"></i> <strong>Ransomware</strong> &mdash; Protection & recovery</div>
                </div>
                <p class="ai-response-desc" style="margin-top:1rem">&#128161; <strong>Pro Tip:</strong> Type <em>"analyze my scans"</em> to get <strong>specific fixes</strong> for every vulnerability found in your NexPent scans &mdash; with exact code to copy and deploy!</p>
            </div>`;
        }

        // Find and return matching entry
        const match = findBestMatch(query);
        if (match) {
            return generateResponse(match);
        }

        // Fallback
        return `<p>${fallbackResponses[Math.floor(Math.random() * fallbackResponses.length)]}</p>`;
    }

    /**
     * Escape HTML entities
     */
    function escapeHtml(text) {
        const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
        return text.replace(/[&<>"']/g, m => map[m]);
    }

    /**
     * Copy code from code block
     */
    function copyCode(btn) {
        const codeBlock = btn.closest(".ai-code-block").querySelector("code");
        if (codeBlock) {
            navigator.clipboard.writeText(codeBlock.textContent).then(() => {
                const original = btn.innerHTML;
                btn.innerHTML = '<i class="fas fa-check"></i> Copied!';
                setTimeout(() => { btn.innerHTML = original; }, 2000);
            });
        }
    }

    // ========== PUBLIC API ==========
    return {
        processQuery,
        getQuickSuggestions: () => quickSuggestions,
        getGreeting: () => greetings[Math.floor(Math.random() * greetings.length)],
        copyCode,
        generateScanContextResponse
    };
})();
