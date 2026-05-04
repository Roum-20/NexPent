/* ============================================
   NexPent — Login Brute-Force Tester Module
   REAL-TIME: Sends actual login requests via
   fetch() and analyzes real server responses.
   ============================================ */

const BruteForceModule = (() => {
    // Common default credentials database
    const defaultCreds = [
        { user: "admin", pass: "admin" },
        { user: "admin", pass: "password" },
        { user: "admin", pass: "123456" },
        { user: "root", pass: "root" },
        { user: "root", pass: "toor" },
        { user: "test", pass: "test" },
        { user: "user", pass: "user" },
        { user: "administrator", pass: "administrator" },
        { user: "admin", pass: "admin123" },
        { user: "guest", pass: "guest" },
    ];

    async function runBruteForce(config, outputEl, progressEl, fillEl, textEl) {
        const { url, userField, passField, usernames, passwords, failText } = config;

        const users = usernames.split("\n").filter((u) => u.trim()).map((u) => u.trim());
        const passes = passwords.split("\n").filter((p) => p.trim()).map((p) => p.trim());
        const totalAttempts = users.length * passes.length;

        const results = {
            target: url,
            totalAttempts,
            found: [],
            tested: 0,
            weakPasswords: [],
            noLockout: true,
            rateLimited: false,
        };

        progressEl.style.display = "flex";

        addLine(outputEl, "info", "[SCAN]", `REAL-TIME brute-force test on: ${url}`);
        addLine(outputEl, "info", "[INFO]", `Users: ${users.length} | Passwords: ${passes.length} | Total combos: ${totalAttempts}`);
        addLine(outputEl, "info", "[INFO]", `User field: "${userField}" | Pass field: "${passField}"`);
        addLine(outputEl, "info", "[INFO]", `Failure indicator: "${failText}"`);
        addLine(outputEl, "warning", "[LIVE]", "⚡ Live HTTP POST requests — testing real login endpoint");
        addLine(outputEl, "system", "[SYS]", "─".repeat(60));

        // Get baseline response (failed login) for comparison
        let baselineBody = "";
        let baselineStatus = 0;
        let baselineLength = 0;
        let baselineRedirect = "";

        try {
            addLine(outputEl, "info", "[BASE]", "Fetching baseline response with invalid credentials...");
            const baseResp = await fetchLogin(url, userField, passField, "invalid_nexpent_user_xxx", "invalid_nexpent_pass_xxx");
            baselineStatus = baseResp.status;
            baselineBody = await baseResp.text();
            baselineLength = baselineBody.length;
            baselineRedirect = baseResp.redirected ? baseResp.url : "";
            addLine(outputEl, "success", "[BASE]", `Baseline: HTTP ${baselineStatus} | ${baselineLength} bytes${baselineRedirect ? ` | Redirect: ${baselineRedirect}` : ""}`);
        } catch (err) {
            addLine(outputEl, "warning", "[BASE]", `Baseline fetch failed: ${err.message}`);
        }
        addLine(outputEl, "system", "[SYS]", "─".repeat(60));

        let attempt = 0;
        let lockoutDetected = false;
        let consecutiveFails = 0;
        let lastResponseTime = 0;

        for (const user of users) {
            if (lockoutDetected) break;

            addLine(outputEl, "info", "[USER]", `Testing username: ${user}`);

            for (const pass of passes) {
                attempt++;
                results.tested = attempt;

                const pct = Math.round((attempt / totalAttempts) * 100);
                fillEl.style.width = pct + "%";
                textEl.textContent = `${attempt}/${totalAttempts}`;

                try {
                    const startTime = performance.now();
                    const resp = await fetchLogin(url, userField, passField, user, pass);
                    const respBody = await resp.text();
                    const elapsed = performance.now() - startTime;

                    // ── Analyze the real response ──
                    const loginResult = analyzeLoginResponse(
                        resp, respBody, elapsed,
                        baselineBody, baselineStatus, baselineLength, baselineRedirect,
                        failText, user, pass,
                        lastResponseTime, consecutiveFails
                    );

                    lastResponseTime = elapsed;

                    if (loginResult.lockout) {
                        lockoutDetected = true;
                        results.noLockout = false;
                        addLine(outputEl, "warning", "[LOCK]", `Account lockout detected! ${loginResult.evidence}`);
                        addLine(outputEl, "success", "[OK]", "Lockout mechanism is working — good security practice.");
                        break;
                    }

                    if (loginResult.rateLimit) {
                        results.rateLimited = true;
                        addLine(outputEl, "warning", "[RATE]", `Rate limiting detected: ${loginResult.evidence}. Slowing down...`);
                        await sleep(3000);
                        consecutiveFails++;
                        continue;
                    }

                    if (loginResult.success) {
                        results.found.push({ username: user, password: pass, evidence: loginResult.evidence });
                        addLine(outputEl, "vuln", "[FOUND]", `✓ Valid credentials: ${user}:${pass}`);
                        addLine(outputEl, "info", "[EVD]", `  Evidence: ${loginResult.evidence}`);
                        consecutiveFails = 0;

                        // Check weak password
                        if (isWeakPassword(pass)) {
                            results.weakPasswords.push({ user, pass, reason: getWeakReason(pass) });
                            addLine(outputEl, "warning", "[WEAK]", `Weak password detected: "${pass}" — ${getWeakReason(pass)}`);
                        }
                    } else {
                        consecutiveFails++;
                        // Only show progress every 10 attempts (don't clutter output with failures)
                        if (attempt % 10 === 0 || attempt === totalAttempts) {
                            addLine(outputEl, "system", `[PROG]`, `Tested ${attempt}/${totalAttempts} combinations...`);
                        }
                    }
                } catch (err) {
                    consecutiveFails++;
                    if (err.message.includes("429") || err.message.includes("Too Many")) {
                        results.rateLimited = true;
                        addLine(outputEl, "warning", "[RATE]", `Rate limiting (429 Too Many Requests). Waiting...`);
                        await sleep(5000);
                    } else {
                        addLine(outputEl, "system", `[${attempt}/${totalAttempts}]`, `${user}:${pass} — Error: ${err.message}`);
                    }
                }
            }
            consecutiveFails = 0;
        }

        addLine(outputEl, "system", "[SYS]", "─".repeat(60));
        addLine(outputEl, "info", "[DONE]", `Brute-force test complete.`);
        addLine(outputEl, "info", "[STAT]", `Tested: ${results.tested} | Found: ${results.found.length}`);

        // Security assessment
        addLine(outputEl, "system", "[SYS]", "─".repeat(60));
        addLine(outputEl, "info", "[ASSESS]", "Security Assessment:");

        if (results.found.length > 0) {
            addLine(outputEl, "error", "[FAIL]", `${results.found.length} valid credential(s) discovered via brute-force.`);
        }

        if (results.noLockout && !lockoutDetected) {
            addLine(outputEl, "warning", "[WARN]", "No account lockout mechanism detected — vulnerable to brute-force!");
        } else if (lockoutDetected) {
            addLine(outputEl, "success", "[PASS]", "Account lockout mechanism detected and functional.");
        }

        if (!results.rateLimited) {
            addLine(outputEl, "warning", "[WARN]", "No rate limiting detected — consider implementing throttling.");
        } else {
            addLine(outputEl, "success", "[PASS]", "Rate limiting detected and functional.");
        }

        if (results.weakPasswords.length > 0) {
            addLine(outputEl, "warning", "[WARN]", `${results.weakPasswords.length} weak password(s) found. Enforce strong password policy.`);
        }

        return results;
    }

    /**
     * Send actual login POST request
     */
    async function fetchLogin(url, userField, passField, username, password) {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 10000);

        const body = `${encodeURIComponent(userField)}=${encodeURIComponent(username)}&${encodeURIComponent(passField)}=${encodeURIComponent(password)}`;

        const resp = await fetch(url, {
            method: "POST",
            mode: "cors",
            headers: {
                "Content-Type": "application/x-www-form-urlencoded",
            },
            body,
            redirect: "follow",
            signal: controller.signal,
        });
        clearTimeout(timer);
        return resp;
    }

    /**
     * Analyze real HTTP response to determine if login was successful.
     * 
     * Strategy: Check failure signals FIRST, then success signals.
     * This prevents false positives from different error message variants.
     */
    function analyzeLoginResponse(resp, body, elapsed, baselineBody, baselineStatus, baselineLength, baselineRedirect, failText, user, pass, lastResponseTime, consecutiveFails) {
        const bodyLower = body.toLowerCase();
        const baselineLower = baselineBody.toLowerCase();

        // ── 1. Check for lockout indicators (always first) ──
        if (resp.status === 423 || resp.status === 403) {
            if (bodyLower.includes("locked") || bodyLower.includes("blocked") || bodyLower.includes("too many attempts")) {
                return { success: false, lockout: true, rateLimit: false, evidence: `HTTP ${resp.status} — account locked` };
            }
        }

        // ── 2. Check for rate limiting ──
        if (resp.status === 429) {
            return { success: false, lockout: false, rateLimit: true, evidence: "HTTP 429 Too Many Requests" };
        }
        if (lastResponseTime > 0 && elapsed > lastResponseTime * 5 && elapsed > 3000) {
            return { success: false, lockout: false, rateLimit: true, evidence: `Response time increased: ${lastResponseTime.toFixed(0)}ms → ${elapsed.toFixed(0)}ms` };
        }

        // ── 3. FAILURE CHECK FIRST — look for ANY failure indicators ──
        // This prevents false positives when servers use different error messages
        const failureIndicators = [
            "invalid", "incorrect", "wrong", "failed", "error", "denied",
            "bad credentials", "authentication failed", "try again",
            "access denied", "invalid password", "invalid username",
            "not found", "unauthorized", "forbidden", "not recognized",
            "does not exist", "no account", "login failed", "sign in failed",
        ];
        for (const indicator of failureIndicators) {
            if (bodyLower.includes(indicator)) {
                return { success: false, lockout: false, rateLimit: false };
            }
        }

        // ── 4. Check HTTP status — 401/403 always means failure ──
        if (resp.status === 401 || resp.status === 403) {
            return { success: false, lockout: false, rateLimit: false };
        }

        // ── 5. Check user-specified failure text ──
        if (failText && failText.trim()) {
            if (bodyLower.includes(failText.toLowerCase())) {
                // Failure text IS present = definite failure
                return { success: false, lockout: false, rateLimit: false };
            }
            // Failure text NOT present — but only treat as success if we also
            // see a positive success signal (don't return success here alone)
        }

        // ── 6. Check for common success indicators ──
        const successIndicators = [
            "welcome", "dashboard", "my account", "profile", "logged in",
            "logout", "sign out", "log out", "you are logged in",
            "successfully", "success",
        ];
        for (const indicator of successIndicators) {
            if (bodyLower.includes(indicator) && !baselineLower.includes(indicator)) {
                return { success: true, lockout: false, rateLimit: false, evidence: `Success indicator "${indicator}" found in response (not in baseline)` };
            }
        }

        // ── 7. Check for redirect difference ──
        if (resp.redirected && resp.url !== baselineRedirect) {
            if (!resp.url.includes("login") && !resp.url.includes("error") && !resp.url.includes("fail")) {
                return { success: true, lockout: false, rateLimit: false, evidence: `Redirect changed: ${baselineRedirect || "none"} → ${resp.url}` };
            }
        }

        // ── 8. Status code changed from error to success ──
        if (resp.status !== baselineStatus && (resp.status === 200 || resp.status === 302)) {
            if (baselineStatus === 401 || baselineStatus === 403) {
                return { success: true, lockout: false, rateLimit: false, evidence: `Status changed: ${baselineStatus} → ${resp.status}` };
            }
        }

        // ── 9. Significant response size change (strict threshold) ──
        if (baselineLength > 0 && resp.status === 200) {
            const diff = body.length - baselineLength;
            const ratio = diff / baselineLength;
            // Only flag as success if response is MUCH larger (>50%) AND
            // doesn't contain a login form (which would mean it's still the login page)
            if (ratio > 0.5 && diff > 200) {
                const hasLoginForm = bodyLower.includes("<form") && (bodyLower.includes("password") || bodyLower.includes("login"));
                if (!hasLoginForm) {
                    return { success: true, lockout: false, rateLimit: false, evidence: `Response size changed: ${baselineLength} → ${body.length} bytes (+${(ratio * 100).toFixed(0)}%) — login form absent` };
                }
            }
        }

        // ── 10. Set-Cookie with session token + status 200 ──
        const setCookie = resp.headers.get("set-cookie") || "";
        if (setCookie && resp.status === 200) {
            if (setCookie.includes("session") || setCookie.includes("token") || setCookie.includes("auth")) {
                // Only if failText was specified AND was absent
                if (failText && failText.trim() && !bodyLower.includes(failText.toLowerCase())) {
                    return { success: true, lockout: false, rateLimit: false, evidence: `Session cookie set + failure text "${failText}" absent` };
                }
            }
        }

        // ── 11. If failText was specified and absent AND status is 200 ──
        // (This is the last resort — only if no failure indicators were found above)
        if (failText && failText.trim() && !bodyLower.includes(failText.toLowerCase()) && resp.status === 200) {
            return { success: true, lockout: false, rateLimit: false, evidence: `Failure text "${failText}" not found in HTTP 200 response` };
        }

        return { success: false, lockout: false, rateLimit: false };
    }

    function isWeakPassword(pass) {
        const weakPatterns = [
            /^(password|123456|admin|root|qwerty|letmein|welcome|monkey|master|dragon)$/i,
            /^(.)\1+$/, // All same characters
            /^[0-9]{1,6}$/, // Short numeric only
            /^[a-z]{1,5}$/i, // Short alpha only
        ];
        return pass.length < 8 || weakPatterns.some((p) => p.test(pass));
    }

    function getWeakReason(pass) {
        if (pass.length < 8) return "Too short (< 8 characters)";
        if (/^[0-9]+$/.test(pass)) return "Numeric only";
        if (/^[a-z]+$/i.test(pass)) return "No numbers or special characters";
        if (/^(password|123456|admin|root|qwerty|letmein)$/i.test(pass)) return "Common dictionary word";
        return "Weak pattern detected";
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

    return { runBruteForce };
})();
