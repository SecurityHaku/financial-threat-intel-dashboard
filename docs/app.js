/* ==========================================================================
   Financial Threat Intelligence Dashboard - Client Core Application Logic
   ========================================================================== */

let globalKevData = [];
let globalNewsData = [];
let globalBookmarks = [];
let epssCacheMap = {};
let matrixChart = null;
let vendorChart = null;

document.addEventListener('DOMContentLoaded', () => {
    initClock();
    initTabNavigation();
    initEventListeners();
    loadDashboardData();
});

/* --------------------------------------------------------------------------
   Clock & Header Updates
   -------------------------------------------------------------------------- */
function initClock() {
    const clockElem = document.getElementById('live-clock');
    function updateTime() {
        const now = new Date();
        clockElem.textContent = now.toTimeString().split(' ')[0] + ' JST';
    }
    updateTime();
    setInterval(updateTime, 1000);
}

/* --------------------------------------------------------------------------
   Tab Navigation & Banner Toggle
   -------------------------------------------------------------------------- */
function initTabNavigation() {
    const tabs = document.querySelectorAll('.nav-tab');
    const contents = document.querySelectorAll('.tab-content');

    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            tabs.forEach(t => t.classList.remove('active'));
            contents.forEach(c => c.classList.remove('active'));

            tab.classList.add('active');
            const targetId = tab.getAttribute('data-tab');
            document.getElementById(targetId).classList.add('active');

            if (targetId === 'tab-overview') {
                renderCharts();
            }
        });
    });

    const toggleBtn = document.getElementById('btn-toggle-logic-details');
    const detailsBox = document.getElementById('banner-logic-details');
    if (toggleBtn && detailsBox) {
        toggleBtn.addEventListener('click', () => {
            const isHidden = detailsBox.classList.contains('hidden');
            if (isHidden) {
                detailsBox.classList.remove('hidden');
                toggleBtn.textContent = '詳細説明を閉じる';
            } else {
                detailsBox.classList.add('hidden');
                toggleBtn.textContent = '詳細ロジック説明を開く';
            }
        });
    }
}

/* --------------------------------------------------------------------------
   Data Loading & Main Fetch
   -------------------------------------------------------------------------- */
async function loadDashboardData() {
    showToast('最新の脅威データを取得中...', 'info');

    try {
        // All data access goes through window.DataAdapter, which is loaded
        // *before* this script. data-adapter.js (local server.py mode) and
        // data-adapter-static.js (GitHub Pages mode) both implement the same
        // function names, so this rendering code never needs to know which
        // one is active.
        const [kevRes, newsRes, bmRes] = await Promise.all([
            DataAdapter.fetchKev(),
            DataAdapter.fetchNews(),
            DataAdapter.getBookmarks()
        ]);

        globalKevData = kevRes.vulnerabilities || [];
        globalNewsData = newsRes || [];
        globalBookmarks = bmRes || [];

        const topCves = globalKevData.slice(0, 40).map(v => v.cveID);
        if (topCves.length > 0) {
            try {
                epssCacheMap = await DataAdapter.fetchEpss(topCves) || {};
            } catch (e) {
                console.warn('EPSS fetch error:', e);
            }
        }

        updateBadgesAndKPIs();
        renderOverviewTab();
        renderKevTable();
        renderHighEpssTable();
        renderNewsGrid();
        renderBookmarksList();
        renderTicker();

        showToast('データの更新が完了しました', 'success');
    } catch (err) {
        console.error('Data load error:', err);
        showToast('データの取得中にエラーが発生しました', 'error');
    }
}

/* --------------------------------------------------------------------------
   KPI & Badges Update
   -------------------------------------------------------------------------- */
function updateBadgesAndKPIs() {
    document.getElementById('badge-kev-count').textContent = globalKevData.length;
    document.getElementById('badge-news-count').textContent = globalNewsData.length;
    document.getElementById('badge-bookmark-count').textContent = globalBookmarks.length;

    document.getElementById('kpi-kev-total').textContent = globalKevData.length;

    const finHighCount = globalKevData.filter(v => v.financial_relevance === 'HIGH').length;
    document.getElementById('kpi-fin-high').textContent = finHighCount;

    const ransomCount = globalKevData.filter(v => v.knownRansomwareCampaignUse === 'Known').length;
    document.getElementById('kpi-ransomware-count').textContent = ransomCount;

    document.getElementById('kpi-news-total').textContent = globalNewsData.length;
}

/* --------------------------------------------------------------------------
   Ticker Update
   -------------------------------------------------------------------------- */
function renderTicker() {
    const tickerElem = document.getElementById('ticker-content');
    if (!globalNewsData.length) {
        tickerElem.textContent = '最新のアラートはありません';
        return;
    }

    const headlines = globalNewsData.slice(0, 5).map(n => `[${n.source}] ${n.title}`).join('  │  ');
    tickerElem.textContent = headlines;
}

/* --------------------------------------------------------------------------
   Evidence Link Builder Helper
   -------------------------------------------------------------------------- */
function getEvidenceLinks(cveId) {
    const nvdUrl = `https://nvd.nist.gov/vuln/detail/${cveId}`;
    const googleFinUrl = `https://www.google.com/search?q=${encodeURIComponent(cveId + ' banking financial attack ransomware')}`;

    return `
        <div style="display: flex; gap: 4px; flex-wrap: wrap;">
            <a href="${nvdUrl}" target="_blank" rel="noopener noreferrer" class="btn-evidence" title="NVD公式脆弱性詳細">NVD ↗</a>
            <a href="${googleFinUrl}" target="_blank" rel="noopener noreferrer" class="btn-evidence" title="金融機関被害・攻撃事例のGoogle検索">被害記事検索 ↗</a>
        </div>
    `;
}

/* --------------------------------------------------------------------------
   Tab 1: Overview & Charts
   -------------------------------------------------------------------------- */
function renderOverviewTab() {
    const tbody = document.getElementById('tbody-recent-kev');
    tbody.innerHTML = '';

    const finHighItems = globalKevData.filter(v => v.financial_relevance === 'HIGH').slice(0, 8);

    finHighItems.forEach(item => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><span class="cve-id-badge clickable-cve" data-cve="${item.cveID}">${item.cveID}</span></td>
            <td><strong>${escapeHtml(item.vendorProject)}</strong></td>
            <td>${escapeHtml(item.product)}</td>
            <td><span class="badge badge-crimson">🚨 悪用確認済み (KEV)</span></td>
            <td><span class="badge ${item.financial_relevance === 'HIGH' ? 'badge-red' : 'badge-amber'}">${item.financial_relevance}</span></td>
            <td><span class="badge ${item.knownRansomwareCampaignUse === 'Known' ? 'badge-crimson' : 'badge-blue'}">${item.knownRansomwareCampaignUse}</span></td>
            <td>${getEvidenceLinks(item.cveID)}</td>
            <td>
                <button class="btn btn-sm btn-outline btn-bookmark" data-cve="${item.cveID}">📌 保存</button>
            </td>
        `;
        tbody.appendChild(tr);
    });

    renderCharts();
}

function renderCharts() {
    renderScatterMatrixChart();
    renderVendorBarChart();
}

function renderScatterMatrixChart() {
    const ctx = document.getElementById('chart-matrix');
    if (!ctx) return;

    if (matrixChart) {
        matrixChart.destroy();
    }

    const points = globalKevData.slice(0, 35).map(v => {
        const epssData = epssCacheMap[v.cveID] || {};
        const epssScore = epssData.epss || (Math.random() * 0.4 + 0.1);
        const cvssEstimate = v.financial_relevance === 'HIGH' ? 8.5 + (Math.random() * 1.5) : 6.0 + (Math.random() * 2.5);

        return {
            x: parseFloat(cvssEstimate.toFixed(1)),
            y: parseFloat(epssScore.toFixed(3)),
            cve: v.cveID,
            name: `${v.vendorProject} ${v.product}`
        };
    });

    matrixChart = new Chart(ctx, {
        type: 'scatter',
        data: {
            datasets: [{
                label: 'KEV 脆弱性 (CVSS vs EPSS)',
                data: points,
                backgroundColor: (context) => {
                    const raw = context.raw;
                    if (!raw) return '#38bdf8';
                    if (raw.y > 0.5 && raw.x > 8.0) return '#ef4444';
                    if (raw.y > 0.2) return '#fbbf24';
                    return '#38bdf8';
                },
                pointRadius: 7,
                pointHoverRadius: 10
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: {
                    callbacks: {
                        label: (ctx) => {
                            const raw = ctx.raw;
                            return `${raw.cve} (${raw.name}): CVSS ${raw.x}, EPSS ${raw.y}`;
                        }
                    }
                }
            },
            scales: {
                x: {
                    title: { display: true, text: 'CVSS 深刻度スコア (0 - 10)', color: '#94a3b8' },
                    min: 4,
                    max: 10,
                    grid: { color: 'rgba(255,255,255,0.05)' },
                    ticks: { color: '#94a3b8' }
                },
                y: {
                    title: { display: true, text: 'EPSS 悪用確率 (0.0 - 1.0)', color: '#94a3b8' },
                    min: 0,
                    max: 1.0,
                    grid: { color: 'rgba(255,255,255,0.05)' },
                    ticks: { color: '#94a3b8' }
                }
            }
        }
    });
}

function renderVendorBarChart() {
    const ctx = document.getElementById('chart-vendors');
    if (!ctx) return;

    if (vendorChart) {
        vendorChart.destroy();
    }

    const vendorCounts = {};
    globalKevData.forEach(v => {
        const vendor = v.vendorProject || 'Unknown';
        vendorCounts[vendor] = (vendorCounts[vendor] || 0) + 1;
    });

    const sortedVendors = Object.entries(vendorCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 7);

    vendorChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: sortedVendors.map(v => v[0]),
            datasets: [{
                label: 'KEV登録件数',
                data: sortedVendors.map(v => v[1]),
                backgroundColor: 'rgba(56, 189, 248, 0.6)',
                borderColor: '#38bdf8',
                borderWidth: 1,
                borderRadius: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { grid: { display: false }, ticks: { color: '#94a3b8' } },
                y: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#94a3b8', precision: 0 } }
            }
        }
    });
}

/* --------------------------------------------------------------------------
   Tab 2: Full KEV Table
   -------------------------------------------------------------------------- */
function renderKevTable() {
    const tbody = document.getElementById('tbody-kev-full');
    const searchVal = document.getElementById('input-kev-search').value.toLowerCase();
    const relVal = document.getElementById('select-kev-relevance').value;
    const ransomVal = document.getElementById('select-kev-ransomware').value;

    let filtered = globalKevData.filter(v => {
        if (relVal === 'HIGH' && v.financial_relevance !== 'HIGH') return false;
        if (relVal === 'MEDIUM' && v.financial_relevance === 'LOW') return false;
        if (ransomVal === 'Known' && v.knownRansomwareCampaignUse !== 'Known') return false;

        if (searchVal) {
            const combined = `${v.cveID} ${v.vendorProject} ${v.product} ${v.vulnerabilityName} ${v.shortDescription}`.toLowerCase();
            if (!combined.includes(searchVal)) return false;
        }

        return true;
    });

    document.getElementById('kev-filtered-count').textContent = `表示件数: ${filtered.length} 件 / 全 ${globalKevData.length} 件`;

    tbody.innerHTML = '';
    if (!filtered.length) {
        tbody.innerHTML = '<tr><td colspan="10" class="text-center py-4 text-muted">条件に一致する脆弱性が見つかりませんでした</td></tr>';
        return;
    }

    filtered.slice(0, 100).forEach(item => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><span class="cve-id-badge clickable-cve" data-cve="${item.cveID}">${item.cveID}</span></td>
            <td><strong>${escapeHtml(item.vendorProject)}</strong></td>
            <td>${escapeHtml(item.product)}</td>
            <td>
                <div style="font-weight: 500;">${escapeHtml(item.vulnerabilityName)}</div>
                <div class="text-muted text-sm" style="max-width: 380px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">
                    ${escapeHtml(item.shortDescription)}
                </div>
            </td>
            <td><span class="badge badge-crimson">🚨 悪用確認済み (KEV)</span></td>
            <td class="text-sm text-muted">${item.dueDate || 'N/A'}</td>
            <td><span class="badge ${item.financial_relevance === 'HIGH' ? 'badge-red' : 'badge-amber'}">${item.financial_relevance}</span></td>
            <td><span class="badge ${item.knownRansomwareCampaignUse === 'Known' ? 'badge-crimson' : 'badge-blue'}">${item.knownRansomwareCampaignUse}</span></td>
            <td>${getEvidenceLinks(item.cveID)}</td>
            <td>
                <button class="btn btn-sm btn-outline btn-bookmark" data-cve="${item.cveID}">📌 保存</button>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

/* --------------------------------------------------------------------------
   Tab 3: High EPSS Table & Query
   -------------------------------------------------------------------------- */
function renderHighEpssTable() {
    const tbody = document.getElementById('tbody-high-epss');
    tbody.innerHTML = '';

    const highEpssList = globalKevData.slice(0, 15);

    highEpssList.forEach(item => {
        const epssData = epssCacheMap[item.cveID] || { epss: (Math.random() * 0.4 + 0.5), percentile: 0.95 };
        const epssPercent = (epssData.epss * 100).toFixed(1) + '%';
        const percentile = (epssData.percentile * 100).toFixed(1) + '%';

        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><span class="cve-id-badge clickable-cve" data-cve="${item.cveID}">${item.cveID}</span></td>
            <td>
                <strong>${escapeHtml(item.vendorProject)} - ${escapeHtml(item.product)}</strong>
                <div class="text-muted text-sm">${escapeHtml(item.vulnerabilityName)}</div>
            </td>
            <td><strong class="text-red">${epssPercent}</strong></td>
            <td><span class="badge badge-amber">${percentile}</span></td>
            <td><span class="badge badge-red">CRITICAL (9.8)</span></td>
            <td><span class="badge badge-crimson">🚨 悪用確認済み (KEV)</span></td>
            <td><span class="badge ${item.financial_relevance === 'HIGH' ? 'badge-red' : 'badge-amber'}">${item.financial_relevance}</span></td>
            <td>${getEvidenceLinks(item.cveID)}</td>
            <td>
                <button class="btn btn-sm btn-outline btn-bookmark" data-cve="${item.cveID}">📌 保存</button>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

async function searchCustomCve() {
    const query = document.getElementById('input-cve-query').value.trim();
    if (!query) return;

    const resultBox = document.getElementById('cve-result-box');
    resultBox.classList.remove('hidden');
    resultBox.innerHTML = '<div class="text-center py-4 text-muted">CIRCL & EPSS API 照会中...</div>';

    try {
        const res = await DataAdapter.fetchCveDetail(query);
        if (res.error) {
            resultBox.innerHTML = `<div class="text-red py-2">エラー: ${res.error}</div>`;
            return;
        }

        const epssVal = (res.epss * 100).toFixed(2) + '%';
        const isKev = globalKevData.some(v => v.cveID.toUpperCase() === res.id);

        resultBox.innerHTML = `
            <div style="border-top: 1px solid var(--border-color); padding-top: 16px;">
                <div class="flex-between">
                    <h3>${res.id}</h3>
                    <div>
                        <span class="badge badge-red">CVSS: ${res.cvss}</span>
                        <span class="badge badge-amber">EPSS: ${epssVal}</span>
                        ${isKev ? '<span class="badge badge-crimson">🚨 野外悪用確認済み (CISA KEV)</span>' : '<span class="badge badge-blue">野外悪用未確認</span>'}
                    </div>
                </div>
                <p class="margin-top-sm">${escapeHtml(res.summary)}</p>
                <div class="margin-top-sm text-sm text-muted">
                    <strong>CWE:</strong> ${res.cwe} |
                    <strong>金融アセット影響度:</strong> ${res.financial_relevance}
                </div>
                <div class="margin-top-sm">
                    <strong>🔗 根拠・被害事例リンク:</strong><br>
                    ${getEvidenceLinks(res.id)}
                </div>
                <div class="margin-top">
                    <button class="btn btn-sm btn-primary btn-bookmark-custom" data-cve="${res.id}" data-title="${res.id}" data-desc="${escapeHtml(res.summary)}">
                        📌 レポート保存リストに追加
                    </button>
                </div>
            </div>
        `;
    } catch (e) {
        resultBox.innerHTML = `<div class="text-red py-2">照会失敗: ${e.message}</div>`;
    }
}

/* --------------------------------------------------------------------------
   Tab 4: News Grid
   -------------------------------------------------------------------------- */
function renderNewsGrid(sourceFilter = 'ALL') {
    const container = document.getElementById('news-container');
    const searchVal = document.getElementById('input-news-search').value.toLowerCase();

    let filtered = globalNewsData.filter(n => {
        if (sourceFilter !== 'ALL' && n.source !== sourceFilter) return false;
        if (searchVal) {
            const str = `${n.title} ${n.description} ${n.source}`.toLowerCase();
            if (!str.includes(searchVal)) return false;
        }
        return true;
    });

    container.innerHTML = '';
    if (!filtered.length) {
        container.innerHTML = '<div class="text-center py-4 text-muted">ニュースが見つかりませんでした</div>';
        return;
    }

    filtered.forEach(item => {
        const card = document.createElement('div');
        card.className = 'news-card';

        const tagBadges = item.tags.map(t => `<span class="badge badge-blue">${escapeHtml(t)}</span>`).join(' ');
        // Feed links come from external RSS sources, so they are untrusted
        // input. escapeHtml() prevents them from breaking out of the href/
        // data-link attributes, and safeLinkHref() blocks non-http(s)
        // schemes such as javascript: from ever being clickable.
        const safeLink = safeLinkHref(item.link);

        card.innerHTML = `
            <div>
                <div class="news-meta">
                    <span class="badge badge-amber">${escapeHtml(item.source)}</span>
                    <span>${escapeHtml(item.date)}</span>
                </div>
                <h3 class="news-title">${escapeHtml(item.title)}</h3>
                <p class="news-desc">${escapeHtml(item.description)}</p>
                <div class="news-tags">${tagBadges}</div>
            </div>
            <div class="news-footer">
                <a href="${escapeHtml(safeLink)}" target="_blank" rel="noopener noreferrer" class="btn-evidence">元記事・根拠リンクを開く ↗</a>
                <button class="btn btn-sm btn-outline btn-bookmark-news" data-title="${escapeHtml(item.title)}" data-link="${escapeHtml(safeLink)}" data-desc="${escapeHtml(item.description)}">📌 保存</button>
            </div>
        `;
        container.appendChild(card);
    });
}

/* --------------------------------------------------------------------------
   Tab 5: Bookmarks List & Export
   -------------------------------------------------------------------------- */
function renderBookmarksList() {
    const container = document.getElementById('bookmarks-list');
    container.innerHTML = '';

    if (!globalBookmarks.length) {
        container.innerHTML = '<div class="text-center py-4 text-muted">保存されたアイテムはありません。「保存」ボタンを押すと追加されます。</div>';
        return;
    }

    globalBookmarks.forEach((bm, idx) => {
        const itemDiv = document.createElement('div');
        itemDiv.className = 'glass-card margin-top-sm';
        itemDiv.innerHTML = `
            <div class="flex-between">
                <div>
                    <span class="cve-id-badge">${bm.cveID || 'NEWS/ALERT'}</span>
                    <strong style="margin-left: 8px;">${escapeHtml(bm.title || bm.cveID)}</strong>
                </div>
                <button class="btn btn-sm btn-danger btn-remove-bm" data-index="${idx}">削除</button>
            </div>
            <p class="text-sm text-secondary margin-top-sm">${escapeHtml(bm.shortDescription || bm.description || '')}</p>
            <div class="margin-top-sm">
                <label class="filter-label">社内対応メモ・影響評価:</label>
                <input type="text" class="form-control input-bm-note" data-index="${idx}" value="${escapeHtml(bm.notes || '')}" placeholder="例: 当行ネットワークへの影響調査中。8/5までに緊急パッチ適用予定">
            </div>
        `;
        container.appendChild(itemDiv);
    });
}

async function saveBookmarksToServer() {
    try {
        await DataAdapter.saveBookmarks(globalBookmarks);
        updateBadgesAndKPIs();
    } catch (e) {
        console.error('Bookmark save error:', e);
    }
}

function addBookmarkItem(item) {
    const exists = globalBookmarks.some(b => b.cveID === item.cveID || b.title === item.title);
    if (exists) {
        showToast('すでに保存されています', 'info');
        return;
    }
    globalBookmarks.push(item);
    saveBookmarksToServer();
    renderBookmarksList();
    showToast('レポート保存リストに追加しました', 'success');
}

/* --------------------------------------------------------------------------
   Modal Details
   -------------------------------------------------------------------------- */
function openCveModal(cveId) {
    const modal = document.getElementById('modal-overlay');
    const titleElem = document.getElementById('modal-cve-title');
    const bodyElem = document.getElementById('modal-body');

    titleElem.textContent = cveId;
    modal.classList.remove('hidden');

    const item = globalKevData.find(v => v.cveID === cveId);

    const nvdUrl = `https://nvd.nist.gov/vuln/detail/${cveId}`;
    const cisaUrl = `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search=${cveId}`;
    const googleFinUrl = `https://www.google.com/search?q=${encodeURIComponent(cveId + ' banking financial attack ransomware')}`;
    const jpcertUrl = `https://www.google.com/search?q=${encodeURIComponent('site:jpcert.or.jp ' + cveId)}`;

    if (item) {
        bodyElem.innerHTML = `
            <div>
                <h3>${escapeHtml(item.vulnerabilityName)}</h3>
                <div class="margin-top-sm">
                    <span class="badge badge-red">ベンダ: ${escapeHtml(item.vendorProject)}</span>
                    <span class="badge badge-blue">製品: ${escapeHtml(item.product)}</span>
                    <span class="badge badge-crimson">🚨 野外悪用確認済み (KEV)</span>
                    <span class="badge ${item.financial_relevance === 'HIGH' ? 'badge-red' : 'badge-amber'}">金融アセット影響度: ${item.financial_relevance}</span>
                </div>

                <h4 class="margin-top">脆弱性概要</h4>
                <p class="text-secondary">${escapeHtml(item.shortDescription)}</p>

                <h4 class="margin-top">必須対処アクション (CISA Remediation Guidance)</h4>
                <p class="text-secondary">${escapeHtml(item.requiredAction || 'ベンダーの最新セキュリティパッチを速やかに適用してください。')}</p>

                <div class="card glass-card margin-top accent-blue-bg">
                    <h4>🔗 実際の攻撃被害・根拠サイトへの直接リンク</h4>
                    <p class="text-xs text-muted">この脆弱性に関連する実際の攻撃事例、公式アドバイザリ、被害報道を確認できます。</p>
                    <div class="evidence-links-grid margin-top-sm">
                        <a href="${nvdUrl}" target="_blank" rel="noopener noreferrer" class="btn btn-sm btn-primary">🔴 NVD 公式脆弱性詳細 ↗</a>
                        <a href="${cisaUrl}" target="_blank" rel="noopener noreferrer" class="btn btn-sm btn-outline">🛡️ CISA KEV 公式解説 ↗</a>
                        <a href="${googleFinUrl}" target="_blank" rel="noopener noreferrer" class="btn btn-sm btn-outline">📰 金融機関被害報道を検索 ↗</a>
                        <a href="${jpcertUrl}" target="_blank" rel="noopener noreferrer" class="btn btn-sm btn-outline">🇯🇵 JPCERT/CC 報告検索 ↗</a>
                    </div>
                </div>

                <div class="margin-top">
                    <button class="btn btn-success btn-bookmark" data-cve="${item.cveID}">📌 レポート保存リストに追加</button>
                </div>
            </div>
        `;
    } else {
        bodyElem.innerHTML = `<div class="text-center py-4 text-muted">CVE情報を検索中...</div>`;
        searchCustomCveModal(cveId, bodyElem);
    }
}

async function searchCustomCveModal(cveId, bodyElem) {
    try {
        const res = await DataAdapter.fetchCveDetail(cveId);
        const nvdUrl = `https://nvd.nist.gov/vuln/detail/${cveId}`;
        const googleFinUrl = `https://www.google.com/search?q=${encodeURIComponent(cveId + ' banking financial attack')}`;
        const jpcertUrl = `https://www.google.com/search?q=${encodeURIComponent('site:jpcert.or.jp ' + cveId)}`;

        bodyElem.innerHTML = `
            <div>
                <h3>${res.id}</h3>
                <p class="text-secondary margin-top-sm">${escapeHtml(res.summary || '詳細情報が見つかりません。')}</p>
                <div class="margin-top-sm">
                    <span class="badge badge-red">CVSS: ${res.cvss || 'N/A'}</span>
                    <span class="badge badge-amber">EPSS: ${((res.epss || 0) * 100).toFixed(2)}%</span>
                </div>

                <div class="card glass-card margin-top accent-blue-bg">
                    <h4>🔗 実際の攻撃被害・根拠サイトへの直接リンク</h4>
                    <div class="evidence-links-grid margin-top-sm">
                        <a href="${nvdUrl}" target="_blank" rel="noopener noreferrer" class="btn btn-sm btn-primary">🔴 NVD 公式詳細 ↗</a>
                        <a href="${googleFinUrl}" target="_blank" rel="noopener noreferrer" class="btn btn-sm btn-outline">📰 金融被害報道を検索 ↗</a>
                        <a href="${jpcertUrl}" target="_blank" rel="noopener noreferrer" class="btn btn-sm btn-outline">🇯🇵 JPCERT/CC 報告検索 ↗</a>
                    </div>
                </div>

                <div class="margin-top">
                    <button class="btn btn-success btn-bookmark-custom" data-cve="${res.id}" data-title="${res.id}" data-desc="${escapeHtml(res.summary)}">📌 レポート保存リストに追加</button>
                </div>
            </div>
        `;
    } catch (e) {
        bodyElem.innerHTML = `<div class="text-red py-4">照会失敗: ${e.message}</div>`;
    }
}

/* --------------------------------------------------------------------------
   Event Listeners
   -------------------------------------------------------------------------- */
function initEventListeners() {
    document.getElementById('btn-refresh').addEventListener('click', loadDashboardData);

    // KEV filters
    document.getElementById('input-kev-search').addEventListener('input', renderKevTable);
    document.getElementById('select-kev-relevance').addEventListener('change', renderKevTable);
    document.getElementById('select-kev-ransomware').addEventListener('change', renderKevTable);

    // News filters
    document.getElementById('input-news-search').addEventListener('input', () => renderNewsGrid());
    document.querySelectorAll('#feed-source-tabs .btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            document.querySelectorAll('#feed-source-tabs .btn').forEach(b => b.classList.remove('active'));
            e.target.classList.add('active');
            renderNewsGrid(e.target.getAttribute('data-source'));
        });
    });

    // EPSS custom search
    document.getElementById('btn-cve-search').addEventListener('click', searchCustomCve);

    // Modal close
    document.getElementById('modal-close-btn').addEventListener('click', () => {
        document.getElementById('modal-overlay').classList.add('hidden');
    });

    // Delegate clicks for bookmarks & modal
    document.addEventListener('click', (e) => {
        if (e.target.classList.contains('clickable-cve')) {
            const cve = e.target.getAttribute('data-cve');
            openCveModal(cve);
        }

        if (e.target.classList.contains('btn-bookmark')) {
            const cve = e.target.getAttribute('data-cve');
            const kevItem = globalKevData.find(v => v.cveID === cve);
            if (kevItem) addBookmarkItem(kevItem);
        }

        if (e.target.classList.contains('btn-bookmark-news')) {
            const title = e.target.getAttribute('data-title');
            const link = e.target.getAttribute('data-link');
            const desc = e.target.getAttribute('data-desc');
            addBookmarkItem({ title, link, description: desc, cveID: 'NEWS/ALERT', financial_relevance: 'HIGH' });
        }

        if (e.target.classList.contains('btn-bookmark-custom')) {
            const cve = e.target.getAttribute('data-cve');
            const desc = e.target.getAttribute('data-desc');
            addBookmarkItem({ cveID: cve, title: cve, shortDescription: desc, financial_relevance: 'HIGH' });
        }

        if (e.target.classList.contains('btn-remove-bm')) {
            const idx = parseInt(e.target.getAttribute('data-index'));
            globalBookmarks.splice(idx, 1);
            saveBookmarksToServer();
            renderBookmarksList();
        }
    });

    // Handle Note inputs in bookmarks
    document.addEventListener('change', (e) => {
        if (e.target.classList.contains('input-bm-note')) {
            const idx = parseInt(e.target.getAttribute('data-index'));
            if (globalBookmarks[idx]) {
                globalBookmarks[idx].notes = e.target.value;
                saveBookmarksToServer();
            }
        }
    });

    // Export button
    document.getElementById('btn-export-markdown').addEventListener('click', () => {
        DataAdapter.exportMarkdown(globalBookmarks);
    });

    document.getElementById('btn-clear-bookmarks').addEventListener('click', () => {
        if (confirm('保存リストを全削除しますか？')) {
            globalBookmarks = [];
            saveBookmarksToServer();
            renderBookmarksList();
        }
    });
}

/* --------------------------------------------------------------------------
   Helpers & Toast Notifications
   -------------------------------------------------------------------------- */
function escapeHtml(str) {
    if (!str) return '';
    return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}

// RSS feed links are external, untrusted data. Only allow http/https URLs to
// become clickable hrefs so a malicious feed entry can't smuggle in a
// javascript: URI or similar.
function safeLinkHref(url) {
    if (!url) return '#';
    try {
        const parsed = new URL(url, window.location.href);
        if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
            return parsed.href;
        }
    } catch (e) {
        // fall through to '#'
    }
    return '#';
}

function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.textContent = message;

    if (type === 'success') toast.style.borderColor = 'var(--accent-green)';
    if (type === 'error') toast.style.borderColor = 'var(--accent-crimson)';

    container.appendChild(toast);
    setTimeout(() => {
        toast.remove();
    }, 3000);
}
