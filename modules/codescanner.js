/* ============================================
   NexPent — Static Code Scanner Module
   ============================================ */

const CodeScannerModule = (() => {
    // Insecure code patterns by language
    const securityRules = {
        python: [
            { id: "PY001", pattern: /eval\s*\(/g, severity: "critical", title: "Dangerous eval() usage", desc: "eval() can execute arbitrary code. Use ast.literal_eval() instead.", cwe: "CWE-95" },
            { id: "PY002", pattern: /exec\s*\(/g, severity: "critical", title: "Dangerous exec() usage", desc: "exec() executes arbitrary code strings. Avoid or sanitize input.", cwe: "CWE-95" },
            { id: "PY003", pattern: /os\.system\s*\(/g, severity: "critical", title: "OS command execution", desc: "os.system() is vulnerable to command injection. Use subprocess with shell=False.", cwe: "CWE-78" },
            { id: "PY004", pattern: /subprocess\.call\s*\([^)]*shell\s*=\s*True/g, severity: "high", title: "Shell=True in subprocess", desc: "shell=True enables shell injection attacks. Pass args as a list instead.", cwe: "CWE-78" },
            { id: "PY005", pattern: /pickle\.loads?\s*\(/g, severity: "high", title: "Insecure deserialization", desc: "Pickle can execute arbitrary code during deserialization. Use json instead.", cwe: "CWE-502" },
            { id: "PY006", pattern: /yaml\.load\s*\([^)]*(?!Loader)/g, severity: "high", title: "Unsafe YAML loading", desc: "yaml.load() without Loader param can execute arbitrary code. Use yaml.safe_load().", cwe: "CWE-502" },
            { id: "PY007", pattern: /md5\s*\(|sha1\s*\(/g, severity: "medium", title: "Weak hash algorithm", desc: "MD5/SHA1 are cryptographically broken. Use SHA-256 or bcrypt.", cwe: "CWE-328" },
            { id: "PY008", pattern: /password\s*=\s*['"][^'"]+['"]/g, severity: "high", title: "Hardcoded password", desc: "Passwords should not be hardcoded. Use environment variables or secrets manager.", cwe: "CWE-798" },
            { id: "PY009", pattern: /flask\.make_response.*\n.*headers/g, severity: "medium", title: "Missing security headers", desc: "Ensure proper security headers (CSP, X-Frame-Options, etc.) are set.", cwe: "CWE-693" },
            { id: "PY010", pattern: /input\s*\(/g, severity: "low", title: "User input without validation", desc: "Validate and sanitize all user input before processing.", cwe: "CWE-20" },
            { id: "PY011", pattern: /DEBUG\s*=\s*True/g, severity: "medium", title: "Debug mode enabled", desc: "Debug mode should be disabled in production.", cwe: "CWE-489" },
            { id: "PY012", pattern: /assert\s+/g, severity: "low", title: "Assert used for validation", desc: "Assert statements can be disabled with -O flag. Use proper validation.", cwe: "CWE-617" },
        ],
        javascript: [
            { id: "JS001", pattern: /eval\s*\(/g, severity: "critical", title: "Dangerous eval() usage", desc: "eval() can execute arbitrary code. Use JSON.parse() for data parsing.", cwe: "CWE-95" },
            { id: "JS002", pattern: /innerHTML\s*=/g, severity: "high", title: "innerHTML assignment", desc: "innerHTML can introduce XSS. Use textContent or sanitize input with DOMPurify.", cwe: "CWE-79" },
            { id: "JS003", pattern: /document\.write\s*\(/g, severity: "high", title: "document.write() usage", desc: "document.write() can be exploited for XSS. Use DOM manipulation methods.", cwe: "CWE-79" },
            { id: "JS004", pattern: /\.outerHTML\s*=/g, severity: "high", title: "outerHTML assignment", desc: "outerHTML can introduce XSS vulnerabilities. Sanitize before assignment.", cwe: "CWE-79" },
            { id: "JS005", pattern: /new\s+Function\s*\(/g, severity: "critical", title: "Dynamic Function constructor", desc: "new Function() is equivalent to eval(). Avoid dynamic code execution.", cwe: "CWE-95" },
            { id: "JS006", pattern: /setTimeout\s*\(\s*['"`]/g, severity: "high", title: "setTimeout with string", desc: "setTimeout with string argument acts like eval(). Pass a function instead.", cwe: "CWE-95" },
            { id: "JS007", pattern: /password\s*[:=]\s*['"][^'"]+['"]/gi, severity: "high", title: "Hardcoded credential", desc: "Credentials should not be hardcoded. Use environment variables.", cwe: "CWE-798" },
            { id: "JS008", pattern: /api[_-]?key\s*[:=]\s*['"][^'"]+['"]/gi, severity: "high", title: "Hardcoded API key", desc: "API keys should not be in source code. Use env vars or secrets manager.", cwe: "CWE-798" },
            { id: "JS009", pattern: /console\.log\s*\(/g, severity: "low", title: "Console.log in code", desc: "Remove console.log statements in production code.", cwe: "CWE-532" },
            { id: "JS010", pattern: /crypto\.createCipher\s*\(/g, severity: "high", title: "Deprecated crypto method", desc: "crypto.createCipher is deprecated. Use crypto.createCipheriv().", cwe: "CWE-327" },
            { id: "JS011", pattern: /Math\.random\s*\(/g, severity: "medium", title: "Insecure random", desc: "Math.random() is not cryptographically secure. Use crypto.getRandomValues().", cwe: "CWE-330" },
            { id: "JS012", pattern: /require\s*\(\s*[^'"`]/g, severity: "medium", title: "Dynamic require", desc: "Dynamic require paths can lead to path traversal. Use static paths.", cwe: "CWE-22" },
        ],
        php: [
            { id: "PHP001", pattern: /\$_GET\s*\[/g, severity: "medium", title: "Direct $_GET usage", desc: "Sanitize all GET parameters before use. Use filter_input().", cwe: "CWE-20" },
            { id: "PHP002", pattern: /\$_POST\s*\[/g, severity: "medium", title: "Direct $_POST usage", desc: "Sanitize all POST parameters before use. Use filter_input().", cwe: "CWE-20" },
            { id: "PHP003", pattern: /mysql_query\s*\(/g, severity: "critical", title: "Deprecated mysql_query", desc: "mysql_* functions are deprecated and vulnerable to SQLi. Use PDO with prepared statements.", cwe: "CWE-89" },
            { id: "PHP004", pattern: /eval\s*\(/g, severity: "critical", title: "Dangerous eval()", desc: "eval() executes arbitrary PHP code. Never use with user input.", cwe: "CWE-95" },
            { id: "PHP005", pattern: /system\s*\(|exec\s*\(|passthru\s*\(|shell_exec\s*\(/g, severity: "critical", title: "Command execution", desc: "OS command execution functions are dangerous. Escape and validate all inputs.", cwe: "CWE-78" },
            { id: "PHP006", pattern: /md5\s*\(/g, severity: "medium", title: "Weak MD5 hashing", desc: "MD5 is broken for security purposes. Use password_hash() with bcrypt.", cwe: "CWE-328" },
            { id: "PHP007", pattern: /extract\s*\(\s*\$_(GET|POST|REQUEST)/g, severity: "critical", title: "extract() on user input", desc: "extract() on superglobals can overwrite variables. Use specific assignments.", cwe: "CWE-621" },
            { id: "PHP008", pattern: /unserialize\s*\(/g, severity: "high", title: "Insecure unserialize", desc: "unserialize() with user data can lead to object injection. Use json_decode().", cwe: "CWE-502" },
            { id: "PHP009", pattern: /include\s*\(\s*\$|require\s*\(\s*\$/g, severity: "critical", title: "Dynamic file inclusion", desc: "Dynamic file inclusion can lead to LFI/RFI. Use whitelisted paths.", cwe: "CWE-98" },
            { id: "PHP010", pattern: /header\s*\(\s*['"]Location:\s*.*\$_/g, severity: "high", title: "Open redirect", desc: "User input in redirects enables open redirect attacks. Validate URLs.", cwe: "CWE-601" },
        ],
        java: [
            { id: "JV001", pattern: /Runtime\.getRuntime\(\)\.exec\s*\(/g, severity: "critical", title: "Command execution", desc: "Runtime.exec() is vulnerable to command injection. Validate and escape inputs.", cwe: "CWE-78" },
            { id: "JV002", pattern: /ObjectInputStream/g, severity: "high", title: "Insecure deserialization", desc: "ObjectInputStream can execute arbitrary code. Implement input validation.", cwe: "CWE-502" },
            { id: "JV003", pattern: /PreparedStatement.*\+\s*['"]/g, severity: "critical", title: "SQL injection in PreparedStatement", desc: "String concatenation in queries defeats PreparedStatement. Use parameterized queries.", cwe: "CWE-89" },
            { id: "JV004", pattern: /MessageDigest\.getInstance\s*\(\s*["']MD5["']\)/g, severity: "medium", title: "Weak MD5 hash", desc: "MD5 is cryptographically broken. Use SHA-256 or stronger.", cwe: "CWE-328" },
            { id: "JV005", pattern: /new\s+Random\s*\(/g, severity: "medium", title: "Insecure random", desc: "java.util.Random is predictable. Use SecureRandom for security.", cwe: "CWE-330" },
            { id: "JV006", pattern: /password\s*=\s*"[^"]+"/g, severity: "high", title: "Hardcoded password", desc: "Passwords must not be hardcoded. Use configuration or secrets manager.", cwe: "CWE-798" },
        ],
        c: [
            { id: "C001", pattern: /gets\s*\(/g, severity: "critical", title: "Dangerous gets()", desc: "gets() has no bounds checking and causes buffer overflow. Use fgets().", cwe: "CWE-120" },
            { id: "C002", pattern: /strcpy\s*\(/g, severity: "high", title: "Unsafe strcpy()", desc: "strcpy() has no bounds checking. Use strncpy() or strlcpy().", cwe: "CWE-120" },
            { id: "C003", pattern: /sprintf\s*\(/g, severity: "high", title: "Unsafe sprintf()", desc: "sprintf() can overflow buffer. Use snprintf() with size limit.", cwe: "CWE-120" },
            { id: "C004", pattern: /strcat\s*\(/g, severity: "high", title: "Unsafe strcat()", desc: "strcat() has no bounds checking. Use strncat() or strlcat().", cwe: "CWE-120" },
            { id: "C005", pattern: /system\s*\(/g, severity: "critical", title: "system() call", desc: "system() is vulnerable to command injection. Use exec() family functions.", cwe: "CWE-78" },
            { id: "C006", pattern: /printf\s*\(\s*[a-zA-Z_]/g, severity: "high", title: "Format string vulnerability", desc: "User-controlled format strings enable arbitrary read/write. Use printf(\"%s\", var).", cwe: "CWE-134" },
            { id: "C007", pattern: /malloc\s*\([^)]*\*[^)]*\)/g, severity: "medium", title: "Integer overflow in malloc", desc: "Multiplication in malloc size can overflow. Check with __builtin_mul_overflow().", cwe: "CWE-190" },
        ],
    };

    function detectLanguage(code, filename) {
        if (filename) {
            const ext = filename.split(".").pop().toLowerCase();
            const langMap = {
                py: "python", js: "javascript", jsx: "javascript", ts: "javascript", tsx: "javascript",
                php: "php", java: "java", c: "c", cpp: "c", h: "c", cs: "java",
                rb: "python", go: "java", html: "javascript",
            };
            return langMap[ext] || "javascript";
        }

        // Auto-detect from code
        if (/import\s+\w+|from\s+\w+\s+import|def\s+\w+|print\s*\(/.test(code)) return "python";
        if (/\$_(GET|POST|REQUEST|SERVER)|<\?php/.test(code)) return "php";
        if (/public\s+(static\s+)?void\s+main|class\s+\w+\s*\{.*public/.test(code)) return "java";
        if (/#include\s*<|int\s+main\s*\(|printf\s*\(/.test(code)) return "c";
        return "javascript";
    }

    function analyzeCode(code, language, filename) {
        const lang = language === "auto" ? detectLanguage(code, filename) : language;
        const rules = securityRules[lang] || securityRules.javascript;
        const findings = [];
        const lines = code.split("\n");

        for (const rule of rules) {
            // Reset regex lastIndex
            rule.pattern.lastIndex = 0;
            let match;
            while ((match = rule.pattern.exec(code)) !== null) {
                // Find line number
                const upToMatch = code.substring(0, match.index);
                const lineNum = upToMatch.split("\n").length;

                findings.push({
                    id: rule.id,
                    severity: rule.severity,
                    title: rule.title,
                    desc: rule.desc,
                    cwe: rule.cwe,
                    line: lineNum,
                    code: lines[lineNum - 1]?.trim() || "",
                    match: match[0],
                });
            }
        }

        // Sort by severity
        const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
        findings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

        return {
            language: lang,
            filename: filename || "pasted_code",
            totalLines: lines.length,
            findings,
            score: calculateSecurityScore(findings, lines.length),
        };
    }

    function calculateSecurityScore(findings, totalLines) {
        if (findings.length === 0) return 100;

        let deductions = 0;
        for (const f of findings) {
            switch (f.severity) {
                case "critical": deductions += 20; break;
                case "high": deductions += 12; break;
                case "medium": deductions += 6; break;
                case "low": deductions += 2; break;
            }
        }

        return Math.max(0, 100 - deductions);
    }

    function renderResults(results, outputEl) {
        outputEl.innerHTML = "";

        const { language, filename, totalLines, findings, score } = results;

        addLine(outputEl, "info", "[SCAN]", `Analyzing: ${filename} (${language})`);
        addLine(outputEl, "info", "[INFO]", `Lines: ${totalLines} | Rules checked: ${(securityRules[language] || []).length}`);
        addLine(outputEl, "system", "[SYS]", "─".repeat(60));

        // Security score
        const scoreClass = score >= 80 ? "success" : score >= 50 ? "warning" : "error";
        addLine(outputEl, scoreClass, "[SCORE]", `Security Score: ${score}/100 ${score >= 80 ? "✓" : score >= 50 ? "⚠" : "✗"}`);
        addLine(outputEl, "system", "[SYS]", "─".repeat(60));

        if (findings.length === 0) {
            addLine(outputEl, "success", "[OK]", "No security issues detected! Code appears secure.");
            return;
        }

        addLine(outputEl, "error", "[ALERT]", `Found ${findings.length} security issue(s)!`);
        addLine(outputEl, "system", "[SYS]", "─".repeat(60));

        const counts = { critical: 0, high: 0, medium: 0, low: 0 };
        findings.forEach((f) => counts[f.severity]++);

        if (counts.critical > 0) addLine(outputEl, "error", "[CRIT]", `Critical: ${counts.critical}`);
        if (counts.high > 0) addLine(outputEl, "vuln", "[HIGH]", `High: ${counts.high}`);
        if (counts.medium > 0) addLine(outputEl, "warning", "[MED]", `Medium: ${counts.medium}`);
        if (counts.low > 0) addLine(outputEl, "info", "[LOW]", `Low: ${counts.low}`);

        addLine(outputEl, "system", "[SYS]", "─".repeat(60));

        for (const f of findings) {
            const sevClass = f.severity === "critical" || f.severity === "high" ? "vuln" : f.severity === "medium" ? "warning" : "info";
            addLine(outputEl, sevClass, `[${f.id}]`, `${f.severity.toUpperCase()}: ${f.title}`);
            addLine(outputEl, "system", "[LINE]", `Line ${f.line}: ${f.code}`);
            addLine(outputEl, "system", "[DESC]", f.desc);
            addLine(outputEl, "system", "[CWE]", f.cwe);
            addLine(outputEl, "system", "[SYS]", "─".repeat(40));
        }

        addLine(outputEl, "info", "[DONE]", "Static analysis complete.");
    }

    function addLine(container, type, time, msg) {
        const line = document.createElement("div");
        line.className = `terminal-line ${type}`;
        line.innerHTML = `<span class="time">${time}</span><span class="msg">${msg}</span>`;
        container.appendChild(line);
        container.scrollTop = container.scrollHeight;
    }

    return { analyzeCode, renderResults, detectLanguage };
})();
