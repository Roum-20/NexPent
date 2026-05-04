/**
 * NexPent Vulnerable Test Server
 * ================================
 * DELIBERATELY VULNERABLE — for testing NexPent VAPT scanner output.
 * DO NOT deploy in production. Run only on localhost.
 * 
 * Vulnerabilities included:
 *  - SQL Injection (error-based, reflected)
 *  - XSS (reflected, stored)
 *  - Weak login (brute-force testable)
 *  - Missing security headers
 *  - CORS wildcard
 *  - Directory listing
 *  - Exposed .env / package.json
 *  - Stack trace exposure
 *  - No rate limiting
 *  - Server version disclosure
 *  - Path traversal
 */

const express = require("express");
const path = require("path");
const fs = require("fs");
const app = express();
const PORT = 3001;

// ─── Middleware ───────────────────────────────────────
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// VULN: CORS wildcard — any origin allowed
app.use((req, res, next) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "*");
    // VULN: No security headers (no CSP, no X-Frame-Options, no HSTS, no X-Content-Type-Options)
    // VULN: Server version disclosure
    res.setHeader("Server", "Apache/2.4.41 (Ubuntu)");
    res.setHeader("X-Powered-By", "Express 4.16.0");
    if (req.method === "OPTIONS") return res.sendStatus(200);
    next();
});

// VULN: PUT/DELETE methods accepted (method tampering)
app.put("/", (req, res) => res.json({ status: "PUT accepted", message: "Resource updated" }));
app.delete("/", (req, res) => res.json({ status: "DELETE accepted", message: "Resource deleted" }));
app.patch("/", (req, res) => res.json({ status: "PATCH accepted", message: "Resource patched" }));

// ─── Simulated "database" ────────────────────────────
const users = [
    { id: 1, username: "admin", password: "admin", role: "administrator", email: "admin@testsite.local" },
    { id: 2, username: "root", password: "root", role: "superuser", email: "root@testsite.local" },
    { id: 3, username: "test", password: "test", role: "user", email: "test@testsite.local" },
    { id: 4, username: "user", password: "user", role: "user", email: "user@testsite.local" },
    { id: 5, username: "guest", password: "guest", role: "guest", email: "guest@testsite.local" },
];

const products = [
    { id: 1, name: "Laptop", price: 999.99, stock: 50 },
    { id: 2, name: "Phone", price: 699.99, stock: 120 },
    { id: 3, name: "Tablet", price: 449.99, stock: 75 },
];

const guestbook = []; // stored XSS target

// ─── Homepage ────────────────────────────────────────
app.get("/", (req, res) => {
    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>VulnTest Site — NexPent Target</title>
    <style>
        *{margin:0;padding:0;box-sizing:border-box}
        body{font-family:'Segoe UI',sans-serif;background:#0a0e1a;color:#e2e8f0;min-height:100vh;display:flex;flex-direction:column;align-items:center}
        .banner{width:100%;padding:1rem 2rem;background:linear-gradient(90deg,#dc2626,#b91c1c);text-align:center;font-weight:700;font-size:0.85rem;letter-spacing:1px;text-transform:uppercase;color:#fff}
        .container{max-width:900px;width:100%;padding:2rem}
        h1{font-size:2.5rem;margin:2rem 0 0.5rem;background:linear-gradient(135deg,#ef4444,#f97316);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
        .subtitle{color:#94a3b8;margin-bottom:2rem;font-size:1.1rem}
        .card-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:1rem;margin:1.5rem 0}
        .card{background:#111827;border:1px solid #1e293b;border-radius:12px;padding:1.25rem;transition:border-color 0.3s}
        .card:hover{border-color:#ef4444}
        .card h3{color:#f87171;font-size:0.95rem;margin-bottom:0.4rem}
        .card p{color:#94a3b8;font-size:0.82rem;line-height:1.5}
        .card a{color:#60a5fa;text-decoration:none;font-size:0.8rem;display:inline-block;margin-top:0.5rem}
        .card a:hover{text-decoration:underline}
        .badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:0.65rem;font-weight:700;margin-left:0.5rem;vertical-align:middle}
        .badge.crit{background:rgba(239,68,68,0.15);color:#ef4444}
        .badge.high{background:rgba(249,115,22,0.15);color:#f97316}
        .badge.med{background:rgba(251,191,36,0.15);color:#fbbf24}
        .footer{margin-top:3rem;padding:1.5rem;text-align:center;color:#475569;font-size:0.75rem;border-top:1px solid #1e293b;width:100%}
        code{background:#1e293b;padding:2px 6px;border-radius:4px;font-size:0.8rem;color:#f87171}
    </style>
</head>
<body>
    <div class="banner">⚠ DELIBERATELY VULNERABLE — FOR NEXPENT VAPT TESTING ONLY ⚠</div>
    <div class="container">
        <h1>🎯 VulnTest Site</h1>
        <p class="subtitle">A deliberately vulnerable web application for testing NexPent scanner output.</p>
        
        <div class="card-grid">
            <div class="card">
                <h3>💉 SQL Injection <span class="badge crit">CRITICAL</span></h3>
                <p>Error-based SQLi via <code>?id=</code> parameter. Responds with SQL error messages.</p>
                <a href="/search?id=1">→ /search?id=1</a>
            </div>
            <div class="card">
                <h3>🔓 XSS Reflection <span class="badge high">HIGH</span></h3>
                <p>Input reflected without sanitization in response body.</p>
                <a href="/search?q=test">→ /search?q=test</a>
            </div>
            <div class="card">
                <h3>🔑 Login (Brute-Force) <span class="badge crit">CRITICAL</span></h3>
                <p>No lockout, no rate limiting. Default creds: admin/admin.</p>
                <a href="/login">→ /login</a>
            </div>
            <div class="card">
                <h3>📁 Exposed Files <span class="badge high">HIGH</span></h3>
                <p>.env, package.json, and git HEAD accessible.</p>
                <a href="/.env">→ /.env</a>
            </div>
            <div class="card">
                <h3>🛡 Missing Headers <span class="badge med">MEDIUM</span></h3>
                <p>No CSP, X-Frame-Options, HSTS, or X-Content-Type-Options.</p>
                <a href="/">→ Check headers</a>
            </div>
            <div class="card">
                <h3>📂 Directory Listing <span class="badge high">HIGH</span></h3>
                <p>Directory listing enabled on /assets/.</p>
                <a href="/assets/">→ /assets/</a>
            </div>
            <div class="card">
                <h3>💥 Stack Traces <span class="badge high">HIGH</span></h3>
                <p>Unhandled errors expose full stack traces.</p>
                <a href="/error">→ /error</a>
            </div>
            <div class="card">
                <h3>🌐 CORS Wildcard <span class="badge high">HIGH</span></h3>
                <p>Access-Control-Allow-Origin: * on all endpoints.</p>
                <a href="/">→ Check CORS</a>
            </div>
            <div class="card">
                <h3>🚶 Path Traversal <span class="badge crit">CRITICAL</span></h3>
                <p>File read via ?file= parameter without sanitization.</p>
                <a href="/file?name=readme.txt">→ /file?name=</a>
            </div>
            <div class="card">
                <h3>👤 IDOR <span class="badge crit">CRITICAL</span></h3>
                <p>User profiles accessible by changing ID parameter.</p>
                <a href="/api/users/1">→ /api/users/1</a>
            </div>
            <div class="card">
                <h3>📝 Stored XSS <span class="badge crit">CRITICAL</span></h3>
                <p>Guestbook stores and renders unsanitized HTML.</p>
                <a href="/guestbook">→ /guestbook</a>
            </div>
            <div class="card">
                <h3>🔧 Admin Panel <span class="badge high">HIGH</span></h3>
                <p>Admin dashboard accessible without authentication.</p>
                <a href="/admin">→ /admin</a>
            </div>
        </div>
    </div>
    <div class="footer">
        VulnTest Site v1.0 — Part of NexPent VAPT Toolkit — For authorized testing only<br>
        Server: Apache/2.4.41 (Ubuntu) | X-Powered-By: Express 4.16.0
    </div>
</body>
</html>`);
});

// ─── VULN: SQL Injection (Error-based) ───────────────
app.get("/search", (req, res) => {
    const id = req.query.id || "";
    const q = req.query.q || "";

    // VULN: SQLi — reflects SQL error signatures when quotes are injected
    if (id) {
        if (id.includes("'") || id.includes('"') || id.includes("--") || id.includes(";")) {
            return res.status(500).send(`<h2>Database Error</h2>
<p>You have an error in your SQL syntax; check the manual near '${id}' at line 1</p>
<pre>mysql_fetch_array(): supplied argument is not a valid MySQL result resource
Query: SELECT * FROM products WHERE id = '${id}'
Error: SQLSTATE[42000]: Syntax error or access violation
Stack: at DBConnection.query (mysql.js:42)
       at ProductController.find (controllers/product.js:18)</pre>`);
        }
        if (/UNION\s+SELECT/i.test(id)) {
            return res.send(`<h2>Search Results</h2>
<table border="1"><tr><th>id</th><th>name</th><th>data</th></tr>
<tr><td>1</td><td>admin</td><td>admin@testsite.local</td></tr>
<tr><td>2</td><td>root</td><td>root@testsite.local</td></tr>
${products.map(p => `<tr><td>${p.id}</td><td>${p.name}</td><td>$${p.price}</td></tr>`).join("")}
</table><p>information_schema tables exposed via UNION injection</p>`);
        }
        if (/SLEEP|WAITFOR|BENCHMARK/i.test(id)) {
            // VULN: Time-based blind SQLi — actually delays response
            const delay = Math.min(parseInt(id.match(/\d+/)?.[0]) || 3, 5);
            return setTimeout(() => {
                res.send(`<p>Query completed after delay.</p>`);
            }, delay * 1000);
        }
        const product = products.find(p => p.id === parseInt(id));
        return res.send(`<h2>Product</h2><p>${product ? product.name + " - $" + product.price : "Not found"}</p>`);
    }

    // VULN: XSS — reflects q parameter without sanitization
    if (q) {
        return res.send(`<h2>Search Results for: ${q}</h2>
<p>Showing results for "<strong>${q}</strong>"</p>
<p>No products matched your search: ${q}</p>
<form action="/search" method="GET">
    <input type="text" name="q" value="${q}" />
    <button type="submit">Search</button>
</form>`);
    }

    res.send(`<h2>Search</h2>
<form action="/search" method="GET">
    <input name="q" placeholder="Search products..." />
    <input name="id" placeholder="Product ID..." />
    <button type="submit">Search</button>
</form>`);
});

// ─── VULN: Login (No lockout, no rate limiting) ──────
app.get("/login", (req, res) => {
    res.send(`<!DOCTYPE html><html><head><title>Login</title>
<style>body{font-family:sans-serif;background:#0a0e1a;color:#e2e8f0;display:flex;justify-content:center;align-items:center;min-height:100vh}
.login-box{background:#111827;padding:2rem;border-radius:12px;border:1px solid #1e293b;width:350px}
h2{color:#f87171;margin-bottom:1rem}input{width:100%;padding:0.6rem;margin:0.3rem 0 0.8rem;border:1px solid #1e293b;border-radius:6px;background:#0a0e1a;color:#e2e8f0}
button{width:100%;padding:0.7rem;border:none;border-radius:6px;background:#ef4444;color:#fff;font-weight:700;cursor:pointer}
.msg{padding:0.5rem;margin-top:0.8rem;border-radius:6px;font-size:0.85rem}</style></head>
<body><div class="login-box"><h2>🔐 Login</h2>
<form method="POST" action="/login">
<label>Username</label><input type="text" name="username" required />
<label>Password</label><input type="password" name="password" required />
<button type="submit">Sign In</button>
</form><p style="color:#475569;font-size:0.75rem;margin-top:1rem">Hint: admin/admin, root/root, test/test</p>
</div></body></html>`);
});

app.post("/login", (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username && u.password === password);

    if (user) {
        // VULN: No HttpOnly/Secure flags on cookie
        res.setHeader("Set-Cookie", `session=abc123token; Path=/`);
        return res.send(`<!DOCTYPE html><html><head><title>Welcome</title></head>
<body style="font-family:sans-serif;background:#0a0e1a;color:#e2e8f0;padding:2rem">
<h1>Welcome, ${user.username}!</h1>
<p>You are logged in as <strong>${user.role}</strong>.</p>
<p>Dashboard loaded. <a href="/logout" style="color:#60a5fa">Logout</a></p>
</body></html>`);
    }

    // VULN: Account enumeration — different messages for invalid user vs wrong password
    const userExists = users.find(u => u.username === username);
    const errorMsg = userExists
        ? "Invalid password for this account"
        : "User not found in the system";

    res.status(401).send(`<!DOCTYPE html><html><head><title>Login Failed</title></head>
<body style="font-family:sans-serif;background:#0a0e1a;color:#e2e8f0;padding:2rem">
<h2 style="color:#ef4444">Login Failed</h2>
<p>${errorMsg}</p>
<a href="/login" style="color:#60a5fa">Try again</a>
</body></html>`);
});

// ─── VULN: IDOR — User profiles by ID ───────────────
app.get("/api/users/:id", (req, res) => {
    const user = users.find(u => u.id === parseInt(req.params.id));
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json({ id: user.id, username: user.username, email: user.email, role: user.role, password: user.password });
});

app.get("/api/users", (req, res) => {
    res.json(users.map(u => ({ id: u.id, username: u.username, email: u.email, role: u.role })));
});

// ─── VULN: Exposed sensitive files ──────────────────
app.get("/.env", (req, res) => {
    const envPath = path.join(__dirname, ".env");
    if (fs.existsSync(envPath)) return res.type("text").send(fs.readFileSync(envPath, "utf8"));
    res.type("text").send("DB_HOST=localhost\nDB_PASS=secret123\nAPI_KEY=sk-test-xxx\n");
});

app.get("/.git/HEAD", (req, res) => {
    res.type("text").send("ref: refs/heads/main\n");
});

// package.json already served by the static middleware below

// ─── VULN: Admin panel without auth ─────────────────
app.get("/admin", (req, res) => {
    res.send(`<html><head><title>Admin Panel</title></head>
<body style="font-family:sans-serif;background:#0a0e1a;color:#e2e8f0;padding:2rem">
<h1 style="color:#f87171">⚙ Admin Dashboard</h1>
<p>Server Status: <span style="color:#34d399">● Online</span></p>
<p>Users: ${users.length} | Products: ${products.length}</p>
<h3>User Management</h3>
<table border="1" cellpadding="8" style="border-collapse:collapse;border-color:#1e293b">
<tr style="background:#1e293b"><th>ID</th><th>Username</th><th>Role</th><th>Email</th></tr>
${users.map(u => `<tr><td>${u.id}</td><td>${u.username}</td><td>${u.role}</td><td>${u.email}</td></tr>`).join("")}
</table></body></html>`);
});

app.get("/admin/dashboard", (req, res) => {
    res.redirect("/admin");
});

app.get("/config", (req, res) => {
    res.json({ db: "mysql://admin:pass@localhost/app", debug: true, env: "development" });
});

app.get("/backup", (req, res) => {
    res.json({ backups: ["db_2026-04-01.sql.gz", "db_2026-03-15.sql.gz"], location: "/var/backups/" });
});

// ─── VULN: Directory listing ────────────────────────
app.get("/assets/", (req, res) => {
    res.send(`<html><head><title>Index of /assets/</title></head>
<body><h1>Index of /assets/</h1><hr><pre>
<a href="../">../</a>
<a href="css/">css/</a>                       2026-04-25 10:00    -
<a href="js/">js/</a>                        2026-04-25 10:00    -
<a href="images/">images/</a>                    2026-04-25 10:00    -
<a href="uploads/">uploads/</a>                   2026-04-25 10:00    -
<a href="config.bak">config.bak</a>                 2026-04-25 10:00    1.2K
<a href="database.sql">database.sql</a>               2026-04-25 10:00    45K
</pre><hr><address>Apache/2.4.41 (Ubuntu) Server at localhost Port 3001</address></body></html>`);
});

// ─── VULN: Path traversal ───────────────────────────
app.get("/file", (req, res) => {
    const name = req.query.name || "";
    if (name.includes("..") && (name.includes("etc/passwd") || name.includes("etc\\passwd"))) {
        return res.type("text").send(`root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin`);
    }
    if (name.includes("..") && name.includes("windows")) {
        return res.type("text").send("[boot loader]\ntimeout=30\ndefault=multi(0)\n");
    }
    res.send(`<p>File: ${name || "none specified"}</p>`);
});

// ─── VULN: Stored XSS — Guestbook ──────────────────
app.get("/guestbook", (req, res) => {
    const entries = guestbook.map(e =>
        `<div style="background:#111827;padding:1rem;border-radius:8px;margin:0.5rem 0;border:1px solid #1e293b">
        <strong>${e.name}</strong>: ${e.message}<br>
        <small style="color:#475569">${e.date}</small></div>`
    ).join("") || "<p style='color:#475569'>No entries yet.</p>";

    res.send(`<html><head><title>Guestbook</title></head>
<body style="font-family:sans-serif;background:#0a0e1a;color:#e2e8f0;padding:2rem;max-width:600px;margin:auto">
<h2>📝 Guestbook</h2>
<form method="POST" action="/guestbook" style="margin:1rem 0">
<input name="name" placeholder="Your name" style="padding:0.5rem;width:100%;margin:0.3rem 0;background:#111827;border:1px solid #1e293b;color:#e2e8f0;border-radius:6px" required />
<textarea name="message" placeholder="Your message (HTML allowed!)" rows="3" style="padding:0.5rem;width:100%;margin:0.3rem 0;background:#111827;border:1px solid #1e293b;color:#e2e8f0;border-radius:6px" required></textarea>
<button type="submit" style="padding:0.6rem 1.5rem;background:#ef4444;color:#fff;border:none;border-radius:6px;cursor:pointer;font-weight:700">Post</button>
</form>
<h3>Entries</h3>${entries}</body></html>`);
});

app.post("/guestbook", (req, res) => {
    // VULN: No sanitization — stored XSS
    guestbook.push({ name: req.body.name, message: req.body.message, date: new Date().toISOString() });
    res.redirect("/guestbook");
});

// ─── VULN: Stack trace exposure ─────────────────────
app.get("/error", (req, res) => {
    res.status(500).send(`<h2>500 Internal Server Error</h2>
<pre>Error: Cannot read property 'id' of undefined
    at ProductController.find (/var/www/app/controllers/ProductController.js:42:18)
    at Layer.handle [as handle_request] (/var/www/app/node_modules/express/lib/router/layer.js:95:5)
    at next (/var/www/app/node_modules/express/lib/router/route.js:144:13)
    at Route.dispatch (/var/www/app/node_modules/express/lib/router/route.js:114:3)
    at process._tickCallback (internal/process/next_tick.js:68:7)

Stack trace at line 42 in /var/www/app/controllers/ProductController.js
Database: mysql://admin:password123@db.internal:3306/production</pre>`);
});

// ─── VULN: Exposed error logs ───────────────────────
app.get("/logs/error.log", (req, res) => {
    res.type("text").send(`[2026-04-25 10:15:03] ERROR: SQL syntax error near '' at line 1 - /var/www/app/models/User.js:28
[2026-04-25 10:15:08] ERROR: Unhandled rejection at Promise - /var/www/app/controllers/Auth.js:55
[2026-04-25 10:16:42] WARNING: Failed login attempt for user 'admin' from 192.168.1.105
[2026-04-25 10:17:01] ERROR: ECONNREFUSED 127.0.0.1:6379 (Redis connection failed)
[2026-04-25 10:18:55] CRITICAL: JWT_SECRET exposed in error response - incident #4521`);
});

// ─── VULN: Null/edge input handling ─────────────────
app.get("/api/product", (req, res) => {
    const id = req.query.id;
    if (id === null || id === "null" || id === "" || id === undefined) {
        return res.status(500).send(`<pre>TypeError: Cannot read properties of null (reading 'toString')
    at Object.getProduct (/var/www/app/services/ProductService.js:15:22)
    at Layer.handle [as handle_request] (express/lib/router/layer.js:95:5)</pre>`);
    }
    const p = products.find(pr => pr.id === parseInt(id));
    res.json(p || { error: "Not found" });
});

// ─── Static file serving (exposes package.json) ─────
app.use(express.static(__dirname));

// ─── 404 Handler ────────────────────────────────────
app.use((req, res) => {
    res.status(404).send(`<h2>404 Not Found</h2><p>Path: ${req.path}</p>`);
});

// ─── Start ──────────────────────────────────────────
app.listen(PORT, () => {
    console.log("");
    console.log("  ╔═══════════════════════════════════════════════════╗");
    console.log("  ║   🎯 NexPent Vulnerable Test Server              ║");
    console.log("  ║   ⚠  DELIBERATELY VULNERABLE — TESTING ONLY      ║");
    console.log("  ╠═══════════════════════════════════════════════════╣");
    console.log(`  ║   🌐 Running at: http://localhost:${PORT}            ║`);
    console.log("  ║                                                   ║");
    console.log("  ║   Vulnerabilities active:                         ║");
    console.log("  ║     • SQL Injection (error-based + blind)         ║");
    console.log("  ║     • XSS (reflected + stored)                    ║");
    console.log("  ║     • Brute-force login (no lockout)              ║");
    console.log("  ║     • CORS wildcard (*)                           ║");
    console.log("  ║     • Missing security headers                    ║");
    console.log("  ║     • Path traversal                              ║");
    console.log("  ║     • Directory listing                           ║");
    console.log("  ║     • Exposed .env / package.json                 ║");
    console.log("  ║     • Stack trace exposure                        ║");
    console.log("  ║     • IDOR on /api/users/:id                      ║");
    console.log("  ║     • Server version disclosure                   ║");
    console.log("  ║     • No rate limiting                            ║");
    console.log("  ╚═══════════════════════════════════════════════════╝");
    console.log("");
    console.log("  Use this URL as target in NexPent: http://localhost:3001");
    console.log("");
});
