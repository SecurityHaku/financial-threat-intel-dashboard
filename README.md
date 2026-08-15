# 🛡️ 金融機関向け サイバー脅威インテリジェンス・ダッシュボード (Financial Cyber Threat Intelligence Dashboard)

完全無料の公開データソース（CISA KEV, EPSS API, JPCERT/CC, CISA Advisories, セキュリティニュースRSS）をリアルタイムで統合・可視化する、ローカル動作型の脅威監視ダッシュボードです。

外部クラウドへのデータ送信は行わず、Python標準ライブラリのみで動くシンプルなローカルWebサーバー（`server.py`）と、素のHTML/CSS/JavaScriptのフロントエンドで構成されています。

## 🌟 主な機能

1. **エグゼクティブ・サマリー & リアルタイム・ステータス**
   - KEV総数、金融インパクト高な脆弱性数、ランサムウェア悪用確認数、最新ニュース数をリアルタイム集計。
2. **CISA KEV (野外悪用済み脆弱性) 監視パネル**
   - 野外悪用（In-the-wild）が確認された脆弱性を一覧表示。金融関連機器（Fortinet, Palo Alto, Citrix, AD, VPN, Banking等）のキーワードで自動タグ付け。
3. **Vulnerability & EPSS Hub (CVSS×EPSS優先度判定)**
   - FIRST.orgのEPSS（悪用確率）とCVSS（深刻度）の2軸で、真に緊急対応が必要なパッチ対象を散布図マトリクス化。個別CVE照会も可能。
4. **脅威ニュース & アグリゲーター**
   - JPCERT/CC、CISA Advisories、SecurityWeek、BleepingComputer、The Hacker Newsを統合し、カテゴリ別フィルターで閲覧可能。
5. **社内報告用レポート出力 (Markdown/CSV)**
   - 注目した脅威アイテムをワンクリックでブックマーク＆対応メモを入力し、CSIRT・金融庁/FISCDES報告用フォーマットでエクスポート。

## 📋 必要環境 (Requirements)

- **Python 3.8 以上**（標準ライブラリのみ使用。追加インストール不要）
- インターネット接続（CISA / FIRST.org / JPCERT/CC 等の公開フィード取得のため）

## 🚀 起動方法

1. `start.bat` をダブルクリックするか、ターミナルで以下を実行します。
   ```bash
   python server.py
   ```
2. 自動的にブラウザが開きます（`http://localhost:8000`）。サーバーは `127.0.0.1`（自分のPCのみ）で待ち受けるため、同じネットワーク上の他の端末からはアクセスできません。

## 📁 プロジェクト構成

```
02_threat-intelligence/
├── server.py        # ローカルAPIサーバー（フィード取得・キャッシュ・集計）
├── index.html        # ダッシュボード画面
├── app.js             # フロントエンドのロジック
├── app.css            # デザイン
├── start.bat          # Windows用の起動ショートカット
└── data/               # 実行時に自動生成（Gitには含めません）
    ├── bookmarks.json  # 保存した脅威アイテム・社内メモ
    └── cache/          # 取得したフィードの一時キャッシュ
```

## 🔒 セキュリティに関する注意

- 本アプリは**個人利用・社内検証用のローカルツール**です。認証機能を持たないため、そのままインターネットに公開したり、社外からアクセス可能なサーバーに配置したりしないでください。
- `data/` フォルダ（保存したブックマークやキャッシュ）は `.gitignore` で除外されており、GitHubには公開されません。社内メモなど機微な情報を含む可能性があるため、意図的に公開する場合を除きコミットしないよう注意してください。
- 外部フィード（CISA / EPSS / RSS）取得はTLS証明書検証を行った上でHTTPS通信します。

## 💰 費用・ライセンス

- 費用: **0円（完全無料）**
- APIキー等の登録も不要です。外部クラウドへのデータ送信も行いません。
- ライセンス: [MIT License](LICENSE)
