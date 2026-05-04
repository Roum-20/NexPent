/* ============================================
   NexPent — Persistent Scan Store
   Saves all scan history & stats to localStorage
   Keyed per user account so data is isolated.
   ============================================ */

const ScanStore = (() => {
    "use strict";

    const MAX_HISTORY = 50; // max entries kept per account

    // ── Storage key per user ──────────────────
    function storeKey() {
        try {
            const session = JSON.parse(sessionStorage.getItem("nexpent_session"));
            return session ? `nexpent_scandata_${session.id}` : "nexpent_scandata_guest";
        } catch {
            return "nexpent_scandata_guest";
        }
    }

    // ── Load persisted data ───────────────────
    function load() {
        try {
            const raw = localStorage.getItem(storeKey());
            if (!raw) return null;
            return JSON.parse(raw);
        } catch {
            return null;
        }
    }

    // ── Save full store ───────────────────────
    function save(data) {
        try {
            localStorage.setItem(storeKey(), JSON.stringify(data));
        } catch (e) {
            console.warn("[ScanStore] Could not save:", e);
        }
    }

    // ── Default structure ─────────────────────
    function defaultStore() {
        return {
            stats: { scans: 0, vulns: 0, critical: 0, reports: 0 },
            history: [],
            scanData: {
                sqli: null, xss: null, bf: null,
                code: null, sub: null, port: null,
                cve: [], owasp: null,
            },
            savedAt: null,
        };
    }

    // ── Add a history entry ───────────────────
    function addHistory(entry) {
        const store = load() || defaultStore();
        if (!Array.isArray(store.history)) store.history = [];
        store.history.unshift({
            ...entry,
            date: new Date().toLocaleDateString(),
            time: new Date().toLocaleTimeString(),
        });
        if (store.history.length > MAX_HISTORY) store.history.length = MAX_HISTORY;
        store.savedAt = Date.now();
        save(store);
    }

    // ── Update stats (incremental) ────────────
    function updateStats(delta) {
        const store = load() || defaultStore();
        if (!store.stats) store.stats = { scans: 0, vulns: 0, critical: 0, reports: 0 };
        if (delta.scans) store.stats.scans += delta.scans;
        if (delta.vulns) store.stats.vulns += delta.vulns;
        if (delta.critical) store.stats.critical += delta.critical;
        if (delta.reports) store.stats.reports += delta.reports;
        store.savedAt = Date.now();
        save(store);
        return store.stats;
    }

    // ── Store a full scan result ──────────────
    function saveScanResult(type, result) {
        const store = load() || defaultStore();
        if (!store.scanData) store.scanData = { sqli: null, xss: null, bf: null, code: null, sub: null, port: null, cve: [], owasp: null };
        store.scanData[type] = result;
        store.savedAt = Date.now();
        save(store);
    }

    // ── Get persisted stats ───────────────────
    function getStats() {
        return (load() || defaultStore()).stats;
    }

    // ── Get persisted history ─────────────────
    function getHistory() {
        return (load() || defaultStore()).history;
    }

    // ── Get a saved scan result ───────────────
    function getScanResult(type) {
        return (load() || defaultStore()).scanData[type] || null;
    }

    // ── Clear all data for current account ────
    function clearAll() {
        localStorage.removeItem(storeKey());
    }

    // ── Restore data into app.js state ────────
    // Called by app.js on init after auth resolves
    function restore(state, updateStatsFn, renderHistoryFn) {
        const store = load();
        if (!store) return;

        // Restore stats
        state.stats.scans = store.stats.scans || 0;
        state.stats.vulns = store.stats.vulns || 0;
        state.stats.critical = store.stats.critical || 0;
        state.stats.reports = store.stats.reports || 0;

        // Restore history
        state.history = store.history || [];

        // Restore scan data
        if (store.scanData) {
            Object.assign(state.scanData, store.scanData);
        }

        // Refresh UI
        updateStatsFn();
        renderHistoryFn();

        const age = store.savedAt ? Math.round((Date.now() - store.savedAt) / 60000) : null;
        console.log(`[ScanStore] Restored data for ${storeKey()}${age !== null ? ` (saved ${age} min ago)` : ""}`);
    }

    return {
        addHistory,
        updateStats,
        saveScanResult,
        getStats,
        getHistory,
        getScanResult,
        clearAll,
        restore,
        load,
    };
})();
