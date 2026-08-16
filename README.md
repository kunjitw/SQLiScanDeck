<div align="center">

# SQLiScanDeck

**貼上請求 → 選參數 → 一鍵背景併發 sqlmap / ghauri**
可攜帶、全程入庫、歷史去重的 SQL Injection 測試駕駛艙。
<sub>繁體中文 · English summary at the bottom ↓</sub>

![SQLiScanDeck 主畫面 — 左側掃描佇列(色燈狀態)+ 中間請求編排 + 右側路徑階層測試紀錄樹,底部常用設置與「將執行」即時指令](docs/demo.png)

</div>

## ⚡ 30 秒看懂

- **這是什麼**:**sqlmap + ghauri** 的圖形操作台。貼一段**原始 HTTP 請求**(例如 Burp 攔到的)或一個 URL,它幫你**抽參數、濾雜訊、背景併發掃描、記錄歷史**。
- **為什麼不直接用 CLI**:一次背景**併發**跑多筆、**全程入庫**(指令 / log / 結果)、**歷史去重**、不用手打一堆 `--level/--risk/--technique` 旗標。
- **開始三步**:① 雙擊 **`bootstrap.bat`**(首次下載)→ ② 雙擊 **`start.bat`**(自動開瀏覽器 `http://127.0.0.1:8776`)→ ③ **貼請求 → 選工具 → 開始掃描**。想零風險先試 → **[試玩內建靶機](#-試玩看看)**。
- **需求 · 本機自用**:Windows 10/11、首次 `bootstrap` 需連網下載;不碰系統 Python、預設只綁 `127.0.0.1`、**無內建認證**。

> ⚠️ **只對你有書面授權的目標使用。** 本機工具;**別把 `data/` 上傳**(含真實請求 / cookie / session)。

## 🧭 跳到你要的

**[安裝與啟動](#-安裝與啟動)** · **[試玩看看](#-試玩看看)** · **[五步教學](#-五步教學)** · **[主要功能](#-主要功能)** · **[安全與授權](#-安全與授權)** · 📸 畫面預覽 / ⚙️ 設定 / 🏗️ 架構 / ❓ FAQ 都在最下方摺疊區

## 🛠️ 安裝與啟動

**不用開終端機、不用裝 Python —— 只有兩個檔要點兩下:**

1. **第一次**:連上網路,**雙擊 `bootstrap.bat`**
   → 自動下載內嵌 Python + sqlmap + ghauri(約數分鐘,只需這一次)。
2. **之後每次**:**雙擊 `start.bat`**
   → 啟動並自動開瀏覽器到 **`http://127.0.0.1:8776`**。

> 🆘 **卡住了 / 引擎燈是紅的?** → 看最下方 **❓ 常見問題**(多半是 `bootstrap` 沒跑完,重跑一次即可)。
> 📦 **可攜帶**:複製整包到別台**已 bootstrap 過**的機器,直接 `start.bat` 就能用(免再下載);**分頁與掃描歷史存在 `data/` 裡,跟著搬過去也還在**。
> 🔌 內網 / 離線無法下載:把同事已 bootstrap 好的整包複製過來即可;完全手動安裝見下方〈手動安裝〉。

## 🕹️ 試玩看看

**專案內附兩個練習靶機,可以零風險先跑過一輪。挑一個開起來就好:**

- **A · SQLite 靶機(最快、免下載)** — 另開終端機跑 `python testlab\vuln_server.py`(只綁 `127.0.0.1:5000`)。
- **B · MySQL/MariaDB 靶機(貼近真實)** — 雙擊 `testlab\start_mysql_lab.bat`,首次會自動下載可攜帶 MariaDB 並建好資料庫(只綁 `127.0.0.1:5001`);玩完雙擊 `stop_mysql_lab.bat`。

**然後在 SQLiScanDeck 掃它:**

1. **貼 URL** — 例如 `http://127.0.0.1:5000/product?id=1`(或 `/user?id=1`、`/search?q=phone`…;MySQL 靶機用 `:5001`)。
2. **選工具 → `開始掃描`**。
3. **看結果** — 幾秒後亮**有漏洞**紅燈;點進去看**即時 log、判定依據、payload**(長相見下方 📸 畫面預覽),右側「測試紀錄樹」也會長出端點。

> ⚠️ 兩個靶機都**故意可被注入**,只能綁 `127.0.0.1`、**絕不可對外**。

## 🚀 五步教學

1. **貼上請求** — 貼原始請求或 URL(或按 **`📋 貼上剪貼簿`**),按 **`解析請求`**。參數分三區:**主參數**(預設勾)、Header、已自動略過(後兩區收合)。
2. **選工具** — **sqlmap**(功能最全)或 **ghauri**(較快、對某些 WAF 較好)。
3. **選模式** — **基本掃描**(無腦套用範本、唯讀看它動了哪些設定)或 **進階掃描**(自由調整所有選項)。
4. **調常用設置 + 挑範本 / 調選項** — 底部**常用設置**一排放最常改的(**強制 HTTPS / HTTP**、隨機 User-Agent…);選一個**範本**後下方**掃描選項**動態顯示;**`將執行`** 即時顯示**實際會跑的指令**。想直接改指令 → 按 **`編輯`**(見下方 💡)。
5. **開始掃描** — 按 **`開始掃描`**、二次確認後背景執行。左側佇列看狀態色、點一筆看即時 log;右側紀錄樹累積歷史。

> 💡 **指令 ↔ 選項雙向連動**:滑鼠移到某個選項 → 指令對應旗標發光;點指令旗標 → 跳到並高亮該設定。按 **`編輯`** 進入手改指令模式(選項變灰鎖定),改完按 **`確定`** 會**反解析**回選項:對得上的旗標亮藍、帶回更新,再解鎖讓你繼續調。

## ✨ 主要功能

- **貼上就解析**:原始請求或 URL → 自動抽 GET / POST / JSON / Cookie / Header 參數。
- **雜訊自動略過**:內建過濾規則(GA、FB pixel、CSRF、ViewState、session…),命中的預設不勾。
- **常用設置一排搞定**:把最常改的設定(**強制 HTTPS / HTTP**、隨機 User-Agent…)釘在指令上方,不用進選項堆裡翻;**要釘哪些可在設定自訂**。
- **HTTPS / HTTP 一鍵切換**:`連線協定` 決定送測用哪個 scheme —— sqlmap 加 `--force-ssl`、ghauri 走對應機制;相對路徑、絕對 URL、裸 URL 三種貼法都聽這個開關。
- **基本 / 進階雙模式**:基本=只挑範本、唯讀顯示;進階=全手動。兩者**送出的指令完全一致**(同一份選項元件,不會漂移)。
- **編輯指令(反解析)**:直接手改整條指令,按確定後盡量**反解析回選項**——對得上的亮藍帶回,對不上的原樣保留。改指令不必怕跟按鈕對不上。
- **指令單一真相來源**:底部預覽由後端用**和實際執行相同的邏輯**(`build_args`)產生 → **看到的就是會跑的**。
- **併發、不阻塞**:背景執行,狀態色一眼看懂(**紅=有洞、綠=無洞、橘=掃描中、灰=其他/中止**)。
- **雙視圖 log + 匯出圖片**:掃描詳情可切 **高亮**(標出判定依據 / 列舉結果)或 **原始**(終端機配色);可只顯示原始輸出,或 **`📷 匯出圖片`** 拖曳選行、調寬高、存 PNG / 複製,方便貼進報告。
- **完整記錄 + 判定依據**:工具、指令、選項、即時 log、DBMS / payload、耗時全存 SQLite,並標出**判斷有洞的證據**。
- **歷史去重**:端點簽名把路徑 id 正規化,重測同 API 會提醒「測過 / 曾有漏洞」。
- **測試紀錄樹**:VSCode 式路徑階層(共用前綴群組、GET/POST 同路徑歸一起),**可依結果篩選**、就地展開/刪除。
- **專案分區 + 分頁入庫**:不同目標分成專案;編排分頁存進 DB,**換台電腦(整包複製)照樣還原**。
- **範本**:sqlmap / ghauri 各自分頁、各自預設、可拖曳排序,一鍵套用。
- **深/淺色 + 方正俐落 UI**,支援 `prefers-reduced-motion`。

## 🔒 安全與授權

- **僅供授權範圍內**的測試;只對有明確書面授權的目標使用。
- **未授權掃描可能違法** —— 依當地法律,未經授權對他人系統測試可能觸法,後果自負。
- **無內建認證**:預設只綁 `127.0.0.1`;若改綁 `0.0.0.0` 對外,請自行加存取控制。含真實請求的欄位(原始請求、分頁內容)只在**回環位址**回傳。
- **`data/` 不要上傳**(含真實請求 / cookie / log / 分頁);`.gitignore` 已排除 `data/`、`python/`、`tools/`。
- **`testlab/` 只能本機**:兩個靶機都故意有洞,**絕不可對外曝露**。
- **授權採 [GNU AGPL-3.0](LICENSE)**(著作權 © 2026 kunjitw):可自由使用、研究、修改,但**任何改作 / 散布 / 架成網路服務,都必須同樣以 AGPL 開源並保留署名** —— 公司無法把它 closed-source 變成自己的產品。
- 本專案**編排** [sqlmap](https://github.com/sqlmapproject/sqlmap)(GPLv2)與 [ghauri](https://github.com/r0oth3x49/ghauri)(MIT),以**獨立子程序**執行、由 `bootstrap` 從官方取得、**不隨附於本專案**,各自依其原授權。

---

<details>
<summary>📸 <b>畫面預覽</b></summary>

**請求編排 —— 選工具 / 模式 / 範本 / 選項,底部常用設置 +「將執行」即時指令 +「編輯」:**

![編排畫面 — sqlmap 掃描選項(LEVEL/RISK/TECHNIQUE/THREADS)、底部常用設置(HTTPS/HTTP、隨機 UA)與實際會執行的指令](docs/compose.png)

**掃描詳情 —— 判定依據、每參數結果、原始請求、雙視圖即時 log(高亮 / 原始):**

![掃描詳情 — ghauri 找到 MySQL 注入,參數結果與命中證據、原始請求、可切高亮/原始的即時 log](docs/detail.png)

**匯出圖片 —— 拖曳選行、渲染顏色、可編輯,存 PNG 或複製到剪貼簿:**

![匯出輸出圖片 modal — 勾選渲染顏色、拖曳選要的行、右下拖曳調寬高,下載 PNG 或複製](docs/export.png)

</details>

<details>
<summary>🧠 <b>三個要知道的觀念</b></summary>

- **簽名去重只影響「顯示」**:路徑 id 正規化成 `{id}` 只是用來分組歷史 / 畫樹;**實際送測的是你貼的原文,路徑原封不動。**
- **過濾規則只是取消勾選**:隨時可手動勾回。灰色地帶(session id、Authorization、第一方 cookie)**預設停用**,亂測可能弄壞你的 session。
- **範本 = 一組掃描選項**,依工具分開,設為預設後每次自動帶入;**常用設置**則是把幾個最常改的旗標釘到指令上方快速調。

</details>

<details>
<summary>⚙️ <b>設定</b></summary>

| 項目 | 說明 |
|---|---|
| 同時併發掃描數 | 背景同時可跑幾筆(預設 3,**改後需重啟**) |
| Web 埠 | 預設 8776(**改後需重啟**) |
| 預設掃描工具 | 載入時預選 sqlmap / ghauri |
| 預設掃描模式 | 每次開啟預設 基本 / 進階 |
| 常用設置(釘選) | 自訂哪些旗標顯示在指令上方的快速列(預設:強制 HTTPS、隨機 User-Agent) |
| 詳情預設 log 視圖 | 打開掃描詳情時預設 高亮 / 原始 |
| IP 自動刷新(秒) | 頁首 IP 徽章更新間隔 |
| 嘗試顯示公網 IP | 關掉可在內網更快(會連 ipify 等第三方) |
| 啟動時自動開瀏覽器 | — |

</details>

<details>
<summary>🏗️ <b>架構與執行模型</b></summary>

```
backend/   FastAPI 後端(跑在內嵌 python 上)
  app.py            API 路由 + 靜態前端 + /api/preview(指令等效預覽)+ 回環位址閘門
  scan_manager.py   併發 / 佇列、即時 log 串流、持久化、強停 / 刪除
  drivers/          sqlmap / ghauri 雙驅動 + build_args(唯一指令來源)
  sqlmap_launch.py / ghauri_launch.py   以內嵌 python 直接跑 CLI 的啟動器
  db.py             SQLite(專案 / 掃描 / 參數歷史 / 規則 / 範本 / 分頁)
  request_parser.py / filters.py / signature.py / ip_utils.py / config.py
web/       單頁前端(index.html / style.css / app.js,無框架)
testlab/   vuln_server.py(SQLite 靶機)、vuln_mysql_server.py + mysql_lab.py(可攜帶 MariaDB 靶機),皆只綁 127.0.0.1
python/    內嵌可攜帶 Python(bootstrap 下載,.gitignore)
tools/     sqlmap / ghauri 原始碼(.gitignore)
data/      執行時建立:DB、logs/、requests/、settings.json(.gitignore)
```

- **兩個引擎都以獨立子程序執行**:用 `-r <原始請求檔>` 送測(**測的就是你貼的原文**),背景執行緒即時串流 stdout。
- **指令單一真相來源**:前端預覽與實際執行共用後端 `build_args()`,不會各寫一套而分歧。
- **敏感內容有回環閘門**:原始請求、分頁內容等只在綁 `127.0.0.1 / localhost / ::1` 時回傳。
- **強制停止**先真的殺掉引擎程序,才標記 killed。

</details>

<details>
<summary>🔧 <b>手動安裝(內網 / 無法 bootstrap)</b></summary>

1. 可攜帶 Python 放到 `python\`,執行 `python\python.exe -m pip install -r backend\requirements.txt`。
2. **sqlmap 原始碼**放到 `tools\sqlmap\`(要有 `sqlmap.py` / `sqlmapapi.py`)。
3. **ghauri 原始碼**放到 `tools\ghauri\`(要有 `ghauri\scripts\ghauri.py`),補相依:`pip install tldextract colorama requests chardet ua_generator`。
4. 執行 `start.bat`(或 `python backend\app.py`)。

</details>

<details>
<summary>❓ <b>常見問題</b></summary>

- **引擎燈紅的** → `tools\sqlmap` / `tools\ghauri` 未就緒,重跑 `bootstrap.bat`。
- **指令預覽顯示錯誤 / 空白** → 後端有更新,**重啟 server** 再硬刷新(`/api/preview` 需新版後端)。
- **在特定專案內按 F5 會怎樣** → 會留在該專案(不會跳回列表);頁面狀態會還原。
- **MySQL 靶機開不起來** → 首次需連網下載 MariaDB;若卡住,`stop_mysql_lab.bat` 後重跑 `start_mysql_lab.bat`。
- **IP 顯示「未能偵測」** → 無法對外的環境(正常,不影響掃描);可到設定關掉公網查詢。
- **改併發數 / 埠沒生效** → 需重啟。
- **刪除 / 新規則沒反應** → 後端功能需重啟 server;前端改動 `Ctrl+F5`。

</details>

<details>
<summary>🌐 <b>English</b></summary>

**SQLiScanDeck** is a graphical cockpit for **sqlmap** and **ghauri**. Paste a raw HTTP request (e.g. from Burp) or a URL; it extracts every testable parameter, auto-unchecks known noise (tracking cookies, CSRF, ViewState…), and runs concurrent background scans in one click. Every run is stored, and revisiting the same API shows *"tested N times / was vulnerable"*.

**Requirements** — Windows 10/11; first `bootstrap` needs internet. Local, single-user, no built-in auth.

**Quick start** — ① run `bootstrap.bat` once, ② double-click `start.bat` (opens `http://127.0.0.1:8776`), ③ **paste → pick tool → Basic/Advanced → Start scan**.

**Try it** — run `python testlab/vuln_server.py` (a deliberately-vulnerable SQLite target bound to `127.0.0.1:5000`), or `testlab\start_mysql_lab.bat` for a portable MariaDB target on `127.0.0.1:5001`, then scan `http://127.0.0.1:5000/product?id=1`.

**Notable** — auto param extraction + noise filters · pinned quick settings (**HTTPS/HTTP toggle**, random UA) above the command · Basic (template-only) vs Advanced mode with an *identical* launch payload · **edit-the-command** mode that reverse-parses back into options · command preview built from the **same** code the launcher runs (no drift) · concurrent scans with a colour board + live log · dual log view (highlighted / raw) with **PNG export** · evidence-based verdicts · **force-stop & delete** · dedup via endpoint signatures (*display only; the engine tests your original request*) · VSCode-style path tree with outcome filters · projects with **DB-persisted tabs** (survive a machine move) · per-tool templates · dark/light theme.

**Security** — authorized testing only (unauthorized scanning may be illegal); local tool with **no built-in auth**, loopback-gated sensitive fields; never publish `data/`; keep `testlab/` bound to loopback.

**License** — **GNU AGPL-3.0** (© 2026 kunjitw): free to use, study, and modify, but any modified / distributed / network-served version must also be released under AGPL with attribution — companies cannot turn it into a closed-source product. It orchestrates sqlmap (GPLv2) and ghauri (MIT) as separate processes, fetched by `bootstrap` and not redistributed here, each under its own license.

</details>
