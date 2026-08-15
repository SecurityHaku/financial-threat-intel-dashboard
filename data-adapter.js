/* ==========================================================================
   Data Adapter — Local Server Edition
   ==========================================================================
   This file talks to server.py's REST API (/api/kev, /api/news, ...). It is
   loaded by index.html when running via `python server.py`.

   The GitHub Pages edition (docs/index.html) loads data-adapter-static.js
   instead, which implements the exact same function names but fetches data
   directly from the public sources in the browser and stores bookmarks in
   localStorage. app.js itself never calls fetch() directly — it always goes
   through window.DataAdapter — so the rendering code works unmodified in
   both editions.
   ========================================================================== */

window.DataAdapter = {
    async fetchKev() {
        return fetch('/api/kev').then(r => r.json());
    },

    async fetchNews() {
        return fetch('/api/news').then(r => r.json());
    },

    async fetchEpss(cveList) {
        if (!cveList || !cveList.length) return {};
        return fetch(`/api/epss?cves=${encodeURIComponent(cveList.join(','))}`).then(r => r.json());
    },

    async fetchCveDetail(cveId) {
        return fetch(`/api/cve?id=${encodeURIComponent(cveId)}`).then(r => r.json());
    },

    async getBookmarks() {
        return fetch('/api/bookmarks').then(r => r.json());
    },

    async saveBookmarks(list) {
        return fetch('/api/bookmarks', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(list)
        });
    },

    exportMarkdown() {
        // server.py builds the Markdown report from its own copy of
        // bookmarks.json and streams it as a download.
        window.open('/api/export?format=markdown', '_blank');
    }
};
