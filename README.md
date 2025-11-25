# ✨ Key Features

**1. Simple Input:** Just put your JS URLs in `js_files.txt` (one per line)

**2. Clean Output:**
- Beautiful HTML report (open in browser) 
- Clean text report (easy to read)
- Color-coded severity levels (HIGH, MEDIUM, LOW, INFO)

**3. Finds:**
- 🔑 **Secrets** (API keys, passwords, tokens, AWS keys, etc.)
- 🌐 **Endpoints** (API URLs, admin panels, internal URLs)
- 🚨 **DOM XSS** vulnerabilities (dangerous sinks)
- 📧 **Interesting data** (emails, S3 buckets, Firebase, comments)

## 🚀 How to Use

**1. Install dependencies:**
```bash
pip3 install aiohttp
```

**2. Create `js_files.txt`:**
```
https://example.com/assets/app.js
https://example.com/static/main.js
https://cdn.example.com/bundle.js
```

**3. Run the scanner:**
```bash
python3 clean_js_scanner.py
```

**4. Check results:**
```
js_scan_results/
├── SECURITY_REPORT.html  ← Open this in browser (beautiful!)
├── SECURITY_REPORT.txt   ← Read in terminal
└── js_files/             ← Downloaded JS files
```

## 📊 What You'll See

The reports show:
- ✅ Summary dashboard with counts
- 🔴 HIGH severity issues (passwords, private keys)
- 🟡 MEDIUM severity issues (DOM XSS, admin panels)
- 🔵 INFO issues (emails, subdomains, comments)
- Each finding clearly labeled with what was found

## 💡 Example Output

```
[✓] Downloaded: app.js
[!] app.js: 12 issues found

📄 FILE: app.js
  [HIGH] AWS Access Key:
    • AKIAIOSFODNN7EXAMPLE
  [MEDIUM] API Endpoint:
    • https://api.example.com/v1/users
    • https://api.example.com/admin/
```

