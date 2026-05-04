/* ============================================
   NexPent — Auth & Theme Module
   Handles: Login, Register, Profile, Theme
   Storage: localStorage
   ============================================ */

const NexAuth = (() => {
    "use strict";

    const STORAGE_KEY = "nexpent_users";
    const SESSION_KEY = "nexpent_session";
    const THEME_KEY = "nexpent_theme";

    // ── Helpers ──────────────────────────────
    function getUsers() {
        return JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]");
    }

    function saveUsers(users) {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(users));
    }

    function getSession() {
        try { return JSON.parse(sessionStorage.getItem(SESSION_KEY)); } catch { return null; }
    }

    function saveSession(user) {
        sessionStorage.setItem(SESSION_KEY, JSON.stringify(user));
    }

    function clearSession() {
        sessionStorage.removeItem(SESSION_KEY);
    }

    // Simple hash (not for real security — frontend only)
    function hashPass(pass) {
        let h = 0;
        for (let i = 0; i < pass.length; i++) {
            h = (Math.imul(31, h) + pass.charCodeAt(i)) | 0;
        }
        return h.toString(36);
    }

    function getInitials(name) {
        return name.trim().split(/\s+/).map(w => w[0].toUpperCase()).slice(0, 2).join("");
    }

    // ── DOM refs ─────────────────────────────
    const overlay = document.getElementById("authOverlay");
    const profileOverlay = document.getElementById("profileOverlay");
    const loginForm = document.getElementById("loginForm");
    const registerForm = document.getElementById("registerForm");
    const loginError = document.getElementById("loginError");
    const registerError = document.getElementById("registerError");
    const profileError = document.getElementById("profileError");
    const themeToggleBtn = document.getElementById("themeToggle");
    const themeIcon = document.getElementById("themeIcon");
    const userAvatarWrap = document.getElementById("userAvatarWrap");
    const userAvatarIcon = document.getElementById("userAvatarIcon");
    const userAvatarInit = document.getElementById("userAvatarInitials");
    const accountDropdown = document.getElementById("accountDropdown");
    const dropdownName = document.getElementById("dropdownName");
    const dropdownEmail = document.getElementById("dropdownEmail");
    const dropdownInitials = document.getElementById("dropdownInitials");

    // ── Sync Assessor Name in Report Generator ──
    function syncAssessor(user) {
        const field = document.getElementById("reportAssessor");
        if (!field) return;
        field.value = user ? user.name : "NexPent Operator";
    }

    // ── Update Topbar UI ─────────────────────
    function updateTopbar(user) {
        if (!user) {
            // Guest state
            userAvatarIcon.style.display = "";
            userAvatarInit.style.display = "none";
            dropdownName.textContent = "Guest";
            dropdownEmail.textContent = "Not signed in";
            dropdownInitials.textContent = "?";
            return;
        }
        const initials = getInitials(user.name);
        userAvatarIcon.style.display = "none";
        userAvatarInit.style.display = "";
        userAvatarInit.textContent = initials;
        dropdownInitials.textContent = initials;
        dropdownName.textContent = user.name;
        dropdownEmail.textContent = user.email;
    }

    // ── Tab switcher ─────────────────────────
    function showTab(tab) {
        loginForm.style.display = tab === "login" ? "" : "none";
        registerForm.style.display = tab === "register" ? "" : "none";
        document.getElementById("tabLogin").classList.toggle("active", tab === "login");
        document.getElementById("tabRegister").classList.toggle("active", tab === "register");
        loginError.textContent = "";
        registerError.textContent = "";
    }

    // ── Login ────────────────────────────────
    function login(e) {
        e.preventDefault();
        const email = document.getElementById("loginEmail").value.trim().toLowerCase();
        const pass = document.getElementById("loginPassword").value;
        const users = getUsers();
        const user = users.find(u => u.email === email && u.password === hashPass(pass));
        if (!user) {
            loginError.textContent = "❌ Invalid email or password.";
            return;
        }
        saveSession(user);
        closeModal();
        updateTopbar(user);
        syncAssessor(user);
        showWelcomeToast(user.name);
    }

    // ── Register ─────────────────────────────
    function register(e) {
        e.preventDefault();
        const name = document.getElementById("regName").value.trim();
        const email = document.getElementById("regEmail").value.trim().toLowerCase();
        const pass = document.getElementById("regPassword").value;
        const users = getUsers();

        if (users.find(u => u.email === email)) {
            registerError.textContent = "❌ An account with this email already exists.";
            return;
        }

        const newUser = { id: Date.now(), name, email, password: hashPass(pass), created: new Date().toISOString() };
        users.push(newUser);
        saveUsers(users);
        saveSession(newUser);
        closeModal();
        updateTopbar(newUser);
        syncAssessor(newUser);
        showWelcomeToast(name);
    }

    // ── Save Profile ─────────────────────────
    function saveProfile(e) {
        e.preventDefault();
        const session = getSession();
        if (!session) return;

        const newName = document.getElementById("profileName").value.trim();
        const newEmail = document.getElementById("profileEmail").value.trim().toLowerCase();
        const newPass = document.getElementById("profilePassword").value;
        const users = getUsers();
        const idx = users.findIndex(u => u.id === session.id);
        if (idx === -1) { profileError.textContent = "Session expired. Please log in again."; return; }

        // Check email uniqueness
        if (users.find(u => u.email === newEmail && u.id !== session.id)) {
            profileError.textContent = "❌ That email is already used by another account.";
            return;
        }

        users[idx].name = newName;
        users[idx].email = newEmail;
        if (newPass) users[idx].password = hashPass(newPass);
        saveUsers(users);
        saveSession(users[idx]);
        updateTopbar(users[idx]);
        syncAssessor(users[idx]);
        closeProfile();

        // Success toast
        const tc = document.getElementById("toastContainer");
        if (tc) {
            const t = document.createElement("div");
            t.className = "toast success";
            t.innerHTML = `<i class="fas fa-circle-check toast-icon"></i><div class="toast-content"><div class="toast-title">Profile Updated</div><div class="toast-msg">Your details have been saved.</div></div>`;
            tc.appendChild(t);
            setTimeout(() => { t.classList.add("removing"); setTimeout(() => t.remove(), 300); }, 3500);
        }
    }

    // ── Logout ───────────────────────────────
    function logout() {
        clearSession();
        accountDropdown.classList.remove("open");
        updateTopbar(null);
        overlay.style.display = "flex";
        showTab("login");
    }

    // ── Modal control ────────────────────────
    function closeModal() { overlay.style.display = "none"; }
    function closeProfile() { profileOverlay.style.display = "none"; }

    function openProfile() {
        const user = getSession();
        if (!user) return;
        document.getElementById("profileName").value = user.name;
        document.getElementById("profileEmail").value = user.email;
        document.getElementById("profilePassword").value = "";
        profileError.textContent = "";
        accountDropdown.classList.remove("open");
        profileOverlay.style.display = "flex";
    }

    // ── Password visibility toggle ───────────
    function togglePass(inputId) {
        const inp = document.getElementById(inputId);
        inp.type = inp.type === "password" ? "text" : "password";
    }

    // ── Theme ────────────────────────────────
    function applyTheme(mode) {
        document.documentElement.setAttribute("data-theme", mode);
        localStorage.setItem(THEME_KEY, mode);
        if (themeIcon) {
            themeIcon.className = mode === "light" ? "fas fa-sun" : "fas fa-moon";
        }
    }

    function toggleTheme() {
        const current = document.documentElement.getAttribute("data-theme") || "dark";
        applyTheme(current === "dark" ? "light" : "dark");
    }

    // ── Welcome Toast ─────────────────────────
    function showWelcomeToast(name) {
        const tc = document.getElementById("toastContainer");
        if (!tc) return;
        const t = document.createElement("div");
        t.className = "toast success";
        t.innerHTML = `<i class="fas fa-circle-check toast-icon"></i><div class="toast-content"><div class="toast-title">Welcome back, ${name}!</div><div class="toast-msg">You're signed in to NexPent.</div></div>`;
        tc.appendChild(t);
        setTimeout(() => { t.classList.add("removing"); setTimeout(() => t.remove(), 300); }, 4000);
    }

    // ── Init ─────────────────────────────────
    function init() {
        // Apply saved theme
        const savedTheme = localStorage.getItem(THEME_KEY) || "dark";
        applyTheme(savedTheme);

        // Theme toggle button
        if (themeToggleBtn) {
            themeToggleBtn.addEventListener("click", toggleTheme);
        }

        // Account dropdown toggle
        const userAvatar = document.getElementById("userAvatar");
        if (userAvatar) {
            userAvatar.addEventListener("click", (e) => {
                e.stopPropagation();
                accountDropdown.classList.toggle("open");
            });
        }

        // Dropdown buttons
        document.getElementById("dropdownProfileBtn")?.addEventListener("click", openProfile);
        document.getElementById("dropdownThemeBtn")?.addEventListener("click", () => {
            toggleTheme();
            accountDropdown.classList.remove("open");
        });
        document.getElementById("dropdownLogoutBtn")?.addEventListener("click", logout);

        // Close dropdown on outside click
        document.addEventListener("click", (e) => {
            if (!userAvatarWrap?.contains(e.target)) {
                accountDropdown?.classList.remove("open");
            }
        });

        // Close profile modal on backdrop click
        profileOverlay?.addEventListener("click", (e) => {
            if (e.target === profileOverlay) closeProfile();
        });

        // Restore session
        const session = getSession();
        if (session) {
            updateTopbar(session);
            syncAssessor(session);
            overlay.style.display = "none";
        } else {
            updateTopbar(null);
            overlay.style.display = "flex";
            showTab("login");
        }
    }

    init();

    // Public API
    return { showTab, login, register, saveProfile, logout, togglePass, closeProfile };
})();
