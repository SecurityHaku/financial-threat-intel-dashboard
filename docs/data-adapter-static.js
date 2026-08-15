/* ==========================================================================
   Data Adapter — GitHub Pages (Static / Client-Only) Edition
   ==========================================================================
   This is the browser-only counterpart to data-adapter.js. There is no
   backend here, so it:

   1. Fetches CISA KEV / EPSS / CVE / RSS data directly from the browser.
      Some of those sources block cross-origin requests (CORS), so this file
      relays those specific requests through public CORS proxy services.
      This is a best-effort convenience for a free demo: proxies can go down
      or start rate-limiting without notice. If a panel shows no data, the
      proxy is most likely temporarily unavailable — try the "更新" button
      later, or run the full local edition (see README) for guaranteed access.
   2. Stores bookmarks in the *visitor's own browser* (localStorage) instead
      of a shared server file — each visitor only ever sees their own saved
      items, and nothing is sent to any server operated by this project.
   3. Builds the Markdown report client-side and triggers a direct file
      download, instead of asking a server to generate it.

   app.js calls these functions through the same window.DataAdapter interface
   used by the local edition, so the UI code itself is identical.
   ========================================================================== */

(function () {
    'use strict';

    /* ------------------------------------------------------------------
       Financial relevance scoring — ported from server.py's
       check_financial_relevance() so both editions tag vulnerabilities
       the same way.
       ------------------------------------------------------------------ */
    const FINANCIAL_KEYWORDS = [
        'banking', 'bank', 'financial', 'swift', 'atm', 'pos', 'payment', 'fintech',
        'fortinet', 'palo alto', 'citrix', 'juniper', 'cisco', 'vpn', 'firewall',
        'active directory', 'ad', 'kerberos', 'exchange', 'outlook', 'microsoft 365',
        'vmware', 'vcenter', 'esxi', 'oracle', 'sap', 'sql', 'database',
        'ransomware', 'lockbit', 'blackcat', 'akira', 'clop', 'zero-day', '0-day',
        'rce', 'remote code execution', 'auth bypass', 'authentication bypass',
        'privilege escalation', 'credential'
    ];
    const HIGH_PRIORITY_KEYWORDS = [
        'banking', 'swift', 'fortinet', 'palo alto', 'citrix', 'vpn',
        'active directory', 'ransomware', 'zero-day', '0-day'
    ];

    function checkFinancialRelevance(text) {
        if (!text) return { score: 'MEDIUM', matches: [] };
        const lower = text.toLowerCase();
        const matches = FINANCIAL_KEYWORDS.filter(kw => lower.includes(kw));
        const hasHigh = HIGH_PRIORITY_KEYWORDS.some(kw => lower.includes(kw));
        let score;
        if (hasHigh || matches.length >= 2) score = 'HIGH';
        else if (matches.length >= 1) score = 'MEDIUM';
        else score = 'LOW';
        return { score, matches };
    }

    /* ------------------------------------------------------------------
       CORS-proxy fallback chain. CISA KEV JSON and several RSS feeds do
       not send Access-Control-Allow-Origin, so a browser fetch straight
       to them is blocked. We try a short list of public proxies in turn.
       ------------------------------------------------------------------ */
    const CORS_PROXIES = [
        (u) => `https://api.allorigins.win/raw?url=${encodeURIComponent(u)}`,
        (u) => `https://corsproxy.io/?url=${encodeURIComponent(u)}`,
        (u) => `https://api.codetabs.com/v1/proxy?quest=${encodeURIComponent(u)}`
    ];

    async function fetchWithTimeout(url, timeoutMs) {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeoutMs);
        try {
            return await fetch(url, { signal: controller.signal });
        } finally {
            clearTimeout(timer);
        }
    }

    async function fetchDirectOrProxied(targetUrl, { direct = false, timeoutMs = 12000 } = {}) {
        if (direct) {
            const res = await fetchWithTimeout(targetUrl, timeoutMs);
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            return res;
        }
        let lastError;
        for (const buildProxyUrl of CORS_PROXIES) {
            try {
                const res = await fetchWithTimeout(buildProxyUrl(targetUrl), timeoutMs);
                if (res.ok) return res;
                lastError = new Error(`HTTP ${res.status} via proxy`);
            } catch (e) {
                lastError = e;
            }
        }
        throw lastError || new Error('All CORS proxies failed');
    }

    /* ------------------------------------------------------------------
       CISA KEV
       ------------------------------------------------------------------ */
    async function fetchKev() {
        const url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
        try {
            const res = await fetchDirectOrProxied(url);
            const data = await res.json();
            const vulns = data.vulnerabilities || [];
            vulns.forEach(v => {
                const searchStr = `${v.vendorProject || ''} ${v.product || ''} ${v.vulnerabilityName || ''} ${v.shortDescription || ''}`;
                const relevance = checkFinancialRelevance(searchStr);
                v.financial_relevance = relevance.score;
                v.financial_tags = relevance.matches;
                v.knownRansomwareCampaignUse = v.knownRansomwareCampaignUse || 'Unknown';
            });
            return { title: data.title, dateReleased: data.dateReleased, count: vulns.length, vulnerabilities: vulns };
        } catch (e) {
            console.warn('[DataAdapter] CISA KEV fetch failed (proxy may be down):', e);
            return { title: 'CISA KEV', dateReleased: '', count: 0, vulnerabilities: [] };
        }
    }

    /* ------------------------------------------------------------------
       RSS / Atom news feeds
       ------------------------------------------------------------------ */
    const NEWS_FEEDS = [
        { name: 'JPCERT/CC (Alerts)', url: 'https://www.jpcert.or.jp/rss/jpcert.rdf', lang: 'JP', direct: false },
        { name: 'CISA Advisories', url: 'https://www.cisa.gov/cybersecurity-advisories/all.xml', lang: 'EN', direct: false },
        { name: 'The Hacker News', url: 'https://feeds.feedburner.com/TheHackersNews', lang: 'EN', direct: false },
        { name: 'Dark Reading', url: 'https://www.darkreading.com/rss.xml', lang: 'EN', direct: true },
        { name: 'SecurityWeek', url: 'https://www.securityweek.com/feed/', lang: 'EN', direct: false }
    ];

    function textOf(el) {
        return el && el.textContent ? el.textContent.trim() : '';
    }

    function extractField(item, candidateTags) {
        for (const tag of candidateTags) {
            const els = item.getElementsByTagName(tag);
            for (const el of els) {
                const txt = textOf(el);
                if (txt) return txt;
            }
        }
        return '';
    }

    function extractLink(item) {
        const linkEls = item.getElementsByTagName('link');
        for (const el of linkEls) {
            const txt = textOf(el);
            if (txt) return txt;
        }
        for (const el of linkEls) {
            const href = el.getAttribute && el.getAttribute('href');
            if (href) return href;
        }
        return '';
    }

    function buildTags(title, cleanDesc) {
        const tags = [];
        const combined = (title + ' ' + cleanDesc).toLowerCase();
        if (combined.includes('ransomware') || combined.includes('ランサムウェア')) tags.push('Ransomware');
        if (combined.includes('kev') || combined.includes('cisa') || combined.includes('野外悪用')) tags.push('CISA KEV');
        if (combined.includes('zero-day') || combined.includes('0-day') || combined.includes('ゼロデイ')) tags.push('Zero-Day');
        if (['bank', 'financial', '金融', '銀行', 'swift', 'atm'].some(k => combined.includes(k))) tags.push('Financial Impact');
        if (['vpn', 'fortinet', 'palo alto', 'citrix', 'juniper', 'cisco', 'firewall'].some(k => combined.includes(k))) tags.push('Edge/VPN');
        if (['active directory', 'ad', 'kerberos', 'windows'].some(k => combined.includes(k))) tags.push('Active Directory');
        if (['cloud', 'aws', 'azure', 'gcp'].some(k => combined.includes(k))) tags.push('Cloud');
        if (!tags.length) tags.push('General Cyber Threat');
        return tags;
    }

    async function fetchOneFeed(feed) {
        const results = [];
        try {
            const res = await fetchDirectOrProxied(feed.url, { direct: feed.direct });
            const text = await res.text();
            const xml = new DOMParser().parseFromString(text, 'text/xml');
            if (xml.querySelector('parsererror')) throw new Error('XML parse error');

            let items = Array.from(xml.getElementsByTagName('item'));
            if (!items.length) items = Array.from(xml.getElementsByTagName('entry'));

            items.slice(0, 15).forEach(item => {
                const title = extractField(item, ['title']) || 'Untitled Security Alert';
                const link = extractLink(item);
                const rawDesc = extractField(item, ['description', 'summary', 'content']);
                const cleanDesc = rawDesc.replace(/<[^>]+>/g, '').trim().slice(0, 240);
                const pubDate = extractField(item, ['pubDate', 'dc:date', 'date', 'updated', 'published']);
                const relevance = checkFinancialRelevance(`${title} ${cleanDesc}`);

                results.push({
                    source: feed.name,
                    lang: feed.lang,
                    title,
                    link,
                    description: cleanDesc || '詳細についてはリンク先の記事を参照してください。',
                    date: pubDate,
                    relevance: relevance.score,
                    tags: buildTags(title, cleanDesc)
                });
            });
        } catch (e) {
            console.warn(`[DataAdapter] feed failed: ${feed.name} (proxy may be down)`, e);
        }
        return results;
    }

    async function fetchNews() {
        const perFeed = await Promise.all(NEWS_FEEDS.map(fetchOneFeed));
        return perFeed.flat();
    }

    /* ------------------------------------------------------------------
       EPSS (CORS-enabled — no proxy needed)
       ------------------------------------------------------------------ */
    async function fetchEpss(cveList) {
        if (!cveList || !cveList.length) return {};
        try {
            const cveStr = cveList.slice(0, 50).join(',');
            const url = `https://api.first.org/data/v1/epss?cve=${encodeURIComponent(cveStr)}`;
            const res = await fetchWithTimeout(url, 12000);
            if (!res.ok) return {};
            const data = await res.json();
            const results = {};
            (data.data || []).forEach(item => {
                results[item.cve] = {
                    epss: parseFloat(item.epss || 0),
                    percentile: parseFloat(item.percentile || 0),
                    date: item.date || ''
                };
            });
            return results;
        } catch (e) {
            console.warn('[DataAdapter] EPSS fetch failed:', e);
            return {};
        }
    }

    /* ------------------------------------------------------------------
       CVE detail (CIRCL — CORS-enabled, no proxy needed)
       ------------------------------------------------------------------ */
    const CVE_ID_PATTERN = /^CVE-\d{4}-\d{4,10}$/;

    async function fetchCveDetail(cveIdRaw) {
        const cveId = (cveIdRaw || '').toUpperCase().trim();
        if (!CVE_ID_PATTERN.test(cveId)) {
            return { id: cveId, error: 'CVE IDの形式が正しくありません（例: CVE-2024-12345）' };
        }
        try {
            const res = await fetchWithTimeout(`https://cve.circl.lu/api/cve/${cveId}`, 12000);
            if (!res.ok) return { id: cveId, error: 'CVE not found' };
            const data = await res.json();
            const cvss = data.cvss || 0;
            const cvss3 = data.cvss3 || cvss;
            const summary = data.summary || 'No summary available.';
            const epssRes = await fetchEpss([cveId]);
            const epssInfo = epssRes[cveId] || { epss: 0, percentile: 0 };
            const relevance = checkFinancialRelevance(`${cveId} ${summary}`);
            return {
                id: cveId,
                summary,
                cvss: cvss3 || cvss,
                cwe: data.cwe || 'N/A',
                epss: epssInfo.epss,
                epss_percentile: epssInfo.percentile,
                references: (data.references || []).slice(0, 8),
                financial_relevance: relevance.score,
                financial_tags: relevance.matches
            };
        } catch (e) {
            return { id: cveId, error: String(e && e.message ? e.message : e) };
        }
    }

    /* ------------------------------------------------------------------
       Bookmarks — stored in the visitor's own browser only.
       ------------------------------------------------------------------ */
    const BOOKMARKS_KEY = 'threatDashboard.bookmarks.v1';

    function getBookmarksSync() {
        try {
            const raw = localStorage.getItem(BOOKMARKS_KEY);
            return raw ? JSON.parse(raw) : [];
        } catch (e) {
            console.warn('[DataAdapter] localStorage read failed:', e);
            return [];
        }
    }

    async function getBookmarks() {
        return getBookmarksSync();
    }

    async function saveBookmarks(list) {
        try {
            localStorage.setItem(BOOKMARKS_KEY, JSON.stringify(list || []));
        } catch (e) {
            console.warn('[DataAdapter] localStorage write failed (storage full or disabled?):', e);
        }
    }

    /* ------------------------------------------------------------------
       Markdown report — generated client-side, same format as the local
       edition's /api/export, downloaded directly via a Blob URL.
       ------------------------------------------------------------------ */
    function exportMarkdown(bookmarks) {
        const list = bookmarks || getBookmarksSync();
        const now = new Date();
        const pad = (n) => String(n).padStart(2, '0');
        const ts = `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())} ${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;

        let md = `# 🛡️ サイバー脅威インテリジェンス・セキュリティ報告サマリー\n\n`;
        md += `**作成日時**: ${ts}\n`;
        md += `**対象件数**: ${list.length} 件\n\n`;
        md += `---\n\n`;

        list.forEach((item, idx) => {
            md += `### ${idx + 1}. ${item.title || item.cveID || 'Threat Item'}\n`;
            md += `- **タイプ/CVE**: \`${item.cveID || 'Alert/News'}\`\n`;
            md += `- **重要度 / 金融影響**: **${item.financial_relevance || 'HIGH'}**\n`;
            if (item.vendorProject) md += `- **ベンダー/製品**: ${item.vendorProject} - ${item.product}\n`;
            if (item.dateAdded) md += `- **KEV登録日**: ${item.dateAdded}\n`;
            if (item.notes) md += `- **社内メモ・対処方針**: ${item.notes}\n`;
            md += `- **詳細概要**: ${item.shortDescription || item.description || ''}\n`;
            if (item.link) md += `- **参照リンク**: [${item.link}](${item.link})\n`;
            md += `\n`;
        });

        const blob = new Blob([md], { type: 'text/markdown;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'Threat_Report.md';
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 2000);
    }

    window.DataAdapter = {
        fetchKev,
        fetchNews,
        fetchEpss,
        fetchCveDetail,
        getBookmarks,
        saveBookmarks,
        exportMarkdown
    };
})();
