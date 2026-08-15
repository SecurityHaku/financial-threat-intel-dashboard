import http.server
import socketserver
import urllib.request
import urllib.parse
import json
import xml.etree.ElementTree as ET
import os
import time
import re
import threading
import sys
import webbrowser
import ssl
import html

PORT = 8000
# Bind to localhost only. This dashboard has no authentication, so listening
# on 0.0.0.0 would let anyone on the same network (or an attacker who gets a
# victim's browser to send a request) read data or write bookmarks.
BIND_HOST = '127.0.0.1'
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
BOOKMARKS_FILE = os.path.join(DATA_DIR, 'bookmarks.json')
CACHE_DIR = os.path.join(DATA_DIR, 'cache')

# Only these files may be served as static assets. This is a small,
# fixed allow-list (rather than "serve whatever path was requested") so a
# request like GET /../server.py or GET /../data/bookmarks.json can never
# escape this folder or expose source code / internal data.
ALLOWED_STATIC_FILES = {'index.html', 'app.js', 'app.css', 'data-adapter.js'}

# A CVE ID always looks like CVE-YYYY-NNNN(...). Validating it before using
# it to build a URL or a cache filename prevents request/path injection.
CVE_ID_PATTERN = re.compile(r'^CVE-\d{4}-\d{4,10}$')

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(CACHE_DIR, exist_ok=True)

if not os.path.exists(BOOKMARKS_FILE):
    with open(BOOKMARKS_FILE, 'w', encoding='utf-8') as f:
        json.dump([], f, ensure_ascii=False, indent=2)

# Use the real, verifying default SSL context. This tool fetches threat
# intelligence feeds (CISA KEV, EPSS, RSS) over HTTPS; disabling certificate
# verification would let a network-level attacker silently swap in fake
# vulnerability data, which is exactly what a threat-intel tool must not allow.
SSL_CONTEXT = ssl.create_default_context()

DEFAULT_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36'
}

FINANCIAL_KEYWORDS = [
    'banking', 'bank', 'financial', 'swift', 'atm', 'pos', 'payment', 'fintech',
    'fortinet', 'palo alto', 'citrix', 'juniper', 'cisco', 'vpn', 'firewall',
    'active directory', 'ad', 'kerberos', 'exchange', 'outlook', 'microsoft 365',
    'vmware', 'vcenter', 'esxi', 'oracle', 'sap', 'sql', 'database',
    'ransomware', 'lockbit', 'blackcat', 'akira', 'clop', 'zero-day', '0-day',
    'rce', 'remote code execution', 'auth bypass', 'authentication bypass',
    'privilege escalation', 'credential'
]

def check_financial_relevance(text):
    if not text:
        return {'score': 'MEDIUM', 'matches': [], 'is_high': False}
    text_lower = text.lower()
    matches = [kw for kw in FINANCIAL_KEYWORDS if kw in text_lower]
    
    high_priority_kw = ['banking', 'swift', 'fortinet', 'palo alto', 'citrix', 'vpn', 'active directory', 'ransomware', 'zero-day', '0-day']
    has_high = any(kw in text_lower for kw in high_priority_kw)
    
    if has_high or len(matches) >= 2:
        score = 'HIGH'
        is_high = True
    elif len(matches) >= 1:
        score = 'MEDIUM'
        is_high = False
    else:
        score = 'LOW'
        is_high = False
        
    return {'score': score, 'matches': matches, 'is_high': is_high}

def fetch_url_cached(url, cache_filename, ttl_seconds=1800, headers=None):
    cache_path = os.path.join(CACHE_DIR, cache_filename)
    now = time.time()
    
    if os.path.exists(cache_path):
        mtime = os.path.getmtime(cache_path)
        if (now - mtime) < ttl_seconds:
            try:
                with open(cache_path, 'r', encoding='utf-8') as f:
                    return f.read()
            except Exception:
                pass
                
    if headers is None:
        headers = DEFAULT_HEADERS
        
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, context=SSL_CONTEXT, timeout=12) as response:
            content = response.read().decode('utf-8', errors='ignore')
            with open(cache_path, 'w', encoding='utf-8') as f:
                f.write(content)
            return content
    except Exception as e:
        print(f"[ERROR] Fetching {url}: {e}")
        if os.path.exists(cache_path):
            with open(cache_path, 'r', encoding='utf-8') as f:
                return f.read()
        return None

def extract_field(item, field_name):
    for child in item:
        tag = child.tag.split('}')[-1].lower() if '}' in child.tag else child.tag.lower()
        if tag == field_name.lower():
            txt = child.text or ''
            if not txt.strip():
                for sub in child:
                    if sub.text:
                        txt += ' ' + sub.text
            return html.unescape(txt.strip())
    return ''

def get_cisa_kev():
    url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
    raw_data = fetch_url_cached(url, 'cisa_kev.json', ttl_seconds=3600)
    if not raw_data:
        return {'vulnerabilities': [], 'count': 0}
        
    try:
        data = json.loads(raw_data)
        vulns = data.get('vulnerabilities', [])
        
        for v in vulns:
            search_str = f"{v.get('vendorProject', '')} {v.get('product', '')} {v.get('vulnerabilityName', '')} {v.get('shortDescription', '')}"
            relevance = check_financial_relevance(search_str)
            v['financial_relevance'] = relevance['score']
            v['financial_tags'] = relevance['matches']
            v['knownRansomwareCampaignUse'] = v.get('knownRansomwareCampaignUse', 'Unknown')
            
        return {
            'title': data.get('title', 'CISA KEV'),
            'dateReleased': data.get('dateReleased', ''),
            'count': len(vulns),
            'vulnerabilities': vulns
        }
    except Exception as e:
        print(f"[ERROR] KEV parsing failed: {e}")
        return {'vulnerabilities': [], 'count': 0}

def get_rss_news():
    feeds = [
        {'name': 'JPCERT/CC (Alerts)', 'url': 'https://www.jpcert.or.jp/rss/jpcert.rdf', 'lang': 'JP'},
        {'name': 'CISA Advisories', 'url': 'https://www.cisa.gov/cybersecurity-advisories/all.xml', 'lang': 'EN'},
        {'name': 'The Hacker News', 'url': 'https://feeds.feedburner.com/TheHackersNews', 'lang': 'EN'},
        {'name': 'Dark Reading', 'url': 'https://www.darkreading.com/rss.xml', 'lang': 'EN'},
        {'name': 'SecurityWeek', 'url': 'https://www.securityweek.com/feed/', 'lang': 'EN'}
    ]
    
    all_news = []
    
    for feed in feeds:
        cache_name = re.sub(r'[^a-zA-Z0-9]', '_', feed['name']) + '.xml'
        xml_str = fetch_url_cached(feed['url'], cache_name, ttl_seconds=1800)
        if not xml_str:
            continue
            
        try:
            clean_xml = re.sub(r'^\s*<\?xml[^>]+\?>', '', xml_str, flags=re.MULTILINE).strip()
            root = ET.fromstring(clean_xml)
            
            items = root.findall('.//item')
            if not items:
                items = root.findall('.//{http://purl.org/rss/1.0/}item')
            if not items:
                items = root.findall('.//{http://www.w3.org/2005/Atom}entry')
                
            for item in items[:15]:
                title = extract_field(item, 'title') or 'Untitled Security Alert'
                link = extract_field(item, 'link') or extract_field(item, 'identifier')
                if not link and 'href' in item.attrib:
                    link = item.attrib['href']
                    
                desc = extract_field(item, 'description') or extract_field(item, 'summary')
                clean_desc = re.sub(r'<[^>]+>', '', desc).strip()[:240]
                
                pub_date = extract_field(item, 'pubdate') or extract_field(item, 'date') or extract_field(item, 'updated')
                
                relevance = check_financial_relevance(f"{title} {clean_desc}")
                
                tags = []
                combined = (title + ' ' + clean_desc).lower()
                if 'ransomware' in combined or 'ランサムウェア' in combined: tags.append('Ransomware')
                if 'kev' in combined or 'cisa' in combined or '野外悪用' in combined: tags.append('CISA KEV')
                if 'zero-day' in combined or '0-day' in combined or 'ゼロデイ' in combined: tags.append('Zero-Day')
                if any(k in combined for k in ['bank', 'financial', '金融', '銀行', 'swift', 'atm']): tags.append('Financial Impact')
                if any(k in combined for k in ['vpn', 'fortinet', 'palo alto', 'citrix', 'juniper', 'cisco', 'firewall']): tags.append('Edge/VPN')
                if any(k in combined for k in ['active directory', 'ad', 'kerberos', 'windows']): tags.append('Active Directory')
                if any(k in combined for k in ['cloud', 'aws', 'azure', 'gcp']): tags.append('Cloud')
                
                if not tags:
                    tags.append('General Cyber Threat')
                    
                all_news.append({
                    'source': feed['name'],
                    'lang': feed['lang'],
                    'title': title,
                    'link': link,
                    'description': clean_desc or '詳細についてはリンク先の記事を参照してください。',
                    'date': pub_date,
                    'relevance': relevance['score'],
                    'tags': tags
                })
        except Exception as e:
            print(f"[ERROR] RSS Parsing {feed['name']}: {e}")
            
    return all_news

def get_epss_scores(cves_list):
    if not cves_list:
        return {}
    cve_str = ','.join(cves_list[:50])
    url = f'https://api.first.org/data/v1/epss?cve={cve_str}'
    cache_key = f"epss_{hash(cve_str)}.json"
    raw_data = fetch_url_cached(url, cache_key, ttl_seconds=86400)
    if not raw_data:
        return {}
    try:
        data = json.loads(raw_data)
        results = {}
        for item in data.get('data', []):
            results[item['cve']] = {
                'epss': float(item.get('epss', 0)),
                'percentile': float(item.get('percentile', 0)),
                'date': item.get('date', '')
            }
        return results
    except Exception as e:
        print(f"[ERROR] EPSS fetch: {e}")
        return {}

def get_cve_detail(cve_id):
    cve_id = cve_id.upper().strip()
    if not CVE_ID_PATTERN.match(cve_id):
        return {'id': cve_id, 'error': 'Invalid CVE ID format (expected e.g. CVE-2024-12345)'}
    url = f'https://cve.circl.lu/api/cve/{cve_id}'
    cache_name = f"cve_{cve_id}.json"
    raw_data = fetch_url_cached(url, cache_name, ttl_seconds=86400)
    if not raw_data:
        return {'id': cve_id, 'error': 'CVE not found'}
    try:
        data = json.loads(raw_data)
        cvss = data.get('cvss', 0)
        cvss3 = data.get('cvss3', cvss)
        cwe = data.get('cwe', 'N/A')
        summary = data.get('summary', 'No summary available.')
        references = data.get('references', [])
        
        epss_res = get_epss_scores([cve_id])
        epss_info = epss_res.get(cve_id, {'epss': 0, 'percentile': 0})
        
        relevance = check_financial_relevance(f"{cve_id} {summary}")
        
        return {
            'id': cve_id,
            'summary': summary,
            'cvss': cvss3 or cvss,
            'cwe': cwe,
            'epss': epss_info['epss'],
            'epss_percentile': epss_info['percentile'],
            'references': references[:8],
            'financial_relevance': relevance['score'],
            'financial_tags': relevance['matches']
        }
    except Exception as e:
        return {'id': cve_id, 'error': str(e)}

class ThreatDashboardHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def send_json(self, data, status=200):
        # No Access-Control-Allow-Origin header is sent: the dashboard page
        # and this API are served from the same origin (localhost:8000), so
        # cross-origin access is never needed. Sending a wildcard "*" here
        # would let *any* website's JavaScript read/write this API (including
        # POST /api/bookmarks) via the visitor's browser - an unnecessary risk
        # for an API that has no authentication at all.
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.end_headers()
        self.wfile.write(json.dumps(data, ensure_ascii=False).encode('utf-8'))

    def do_OPTIONS(self):
        self.send_response(204)
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        if path == '/api/kev':
            kev_data = get_cisa_kev()
            self.send_json(kev_data)
        elif path == '/api/news':
            news = get_rss_news()
            self.send_json(news)
        elif path == '/api/epss':
            cves = query.get('cves', [''])[0].split(',')
            cves = [c.strip() for c in cves if c.strip()]
            epss_data = get_epss_scores(cves)
            self.send_json(epss_data)
        elif path == '/api/cve':
            cve_id = query.get('id', [''])[0]
            if not cve_id:
                self.send_json({'error': 'Missing id parameter'}, 400)
            else:
                detail = get_cve_detail(cve_id)
                self.send_json(detail)
        elif path == '/api/bookmarks':
            if os.path.exists(BOOKMARKS_FILE):
                with open(BOOKMARKS_FILE, 'r', encoding='utf-8') as f:
                    bm = json.load(f)
            else:
                bm = []
            self.send_json(bm)
        elif path == '/api/export':
            format_type = query.get('format', ['markdown'])[0]
            if os.path.exists(BOOKMARKS_FILE):
                with open(BOOKMARKS_FILE, 'r', encoding='utf-8') as f:
                    bm = json.load(f)
            else:
                bm = []
                
            if format_type == 'markdown':
                md = "# 🛡️ サイバー脅威インテリジェンス・セキュリティ報告サマリー\n\n"
                md += f"**作成日時**: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                md += f"**対象件数**: {len(bm)} 件\n\n"
                md += "---\n\n"
                
                for idx, item in enumerate(bm, 1):
                    md += f"### {idx}. {item.get('title', item.get('cveID', 'Threat Item'))}\n"
                    md += f"- **タイプ/CVE**: `{item.get('cveID', 'Alert/News')}`\n"
                    md += f"- **重要度 / 金融影響**: **{item.get('financial_relevance', 'HIGH')}**\n"
                    if item.get('vendorProject'):
                        md += f"- **ベンダー/製品**: {item.get('vendorProject')} - {item.get('product')}\n"
                    if item.get('dateAdded'):
                        md += f"- **KEV登録日**: {item.get('dateAdded')}\n"
                    if item.get('notes'):
                        md += f"- **社内メモ・対処方針**: {item.get('notes')}\n"
                    md += f"- **詳細概要**: {item.get('shortDescription', item.get('description', ''))}\n"
                    if item.get('link'):
                        md += f"- **参照リンク**: [{item.get('link')}]({item.get('link')})\n"
                    md += "\n"
                
                self.send_response(200)
                self.send_header('Content-Type', 'text/markdown; charset=utf-8')
                self.send_header('Content-Disposition', 'attachment; filename="Threat_Report.md"')
                self.end_headers()
                self.wfile.write(md.encode('utf-8'))
            else:
                self.send_json({'error': 'Unsupported format'}, 400)
        else:
            # Map the request to one of a fixed set of known-safe filenames.
            # Anything not in ALLOWED_STATIC_FILES (including "..", absolute
            # paths, or requests for server.py / data/*) falls back to
            # index.html instead of being read from disk, so a path-traversal
            # request can never reach a file outside this allow-list.
            rel_path = urllib.parse.unquote(path).lstrip('/')
            if rel_path not in ALLOWED_STATIC_FILES:
                rel_path = 'index.html'
            local_path = os.path.join(BASE_DIR, rel_path)

            try:
                with open(local_path, 'rb') as f:
                    content = f.read()
                
                ext = os.path.splitext(local_path)[1].lower()
                mime = {
                    '.html': 'text/html; charset=utf-8',
                    '.css': 'text/css; charset=utf-8',
                    '.js': 'application/javascript; charset=utf-8',
                    '.json': 'application/json; charset=utf-8',
                    '.png': 'image/png',
                    '.jpg': 'image/jpeg',
                    '.svg': 'image/svg+xml',
                    '.ico': 'image/x-icon'
                }.get(ext, 'application/octet-stream')
                
                self.send_response(200)
                self.send_header('Content-Type', mime)
                self.end_headers()
                self.wfile.write(content)
            except Exception as e:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b'File Not Found')

    def do_POST(self):
        path = self.path
        if path == '/api/bookmarks':
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8')
            try:
                bm_data = json.loads(body)
                with open(BOOKMARKS_FILE, 'w', encoding='utf-8') as f:
                    json.dump(bm_data, f, ensure_ascii=False, indent=2)
                self.send_json({'status': 'success', 'count': len(bm_data)})
            except Exception as e:
                self.send_json({'error': str(e)}, 400)
        else:
            self.send_json({'error': 'Endpoint not found'}, 404)

class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True

def run_server():
    server = ThreadedHTTPServer((BIND_HOST, PORT), ThreatDashboardHandler)
    print(f"============================================================")
    print(f" 🛡️ 金融サイバー脅威インテリジェンス・ダッシュボード 起動中")
    print(f" 🌐 URL: http://localhost:{PORT}")
    print(f" 📊 バックエンドAPI & RSSアグリゲーター準備完了")
    print(f"============================================================")
    
    threading.Timer(1.2, lambda: webbrowser.open(f'http://localhost:{PORT}')).start()
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nサーバーを停止しています...")
        server.shutdown()

if __name__ == '__main__':
    run_server()
