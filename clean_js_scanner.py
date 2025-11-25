#!/usr/bin/env python3
"""
Clean JS Security Scanner
Reads URLs from js_files.txt and produces easy-to-read results
"""

import os
import re
import sys
import asyncio
import aiohttp
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse

# Colors for terminal output
class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def print_banner():
    banner = f"""
{Colors.CYAN}╔═══════════════════════════════════════════════════════╗
║          Clean JS Security Scanner v1.0            ║
║          Easy-to-Read Security Analysis            ║
╚═══════════════════════════════════════════════════════╝{Colors.RESET}
"""
    print(banner)

def print_info(msg):
    print(f"{Colors.BLUE}[ℹ]{Colors.RESET} {msg}")

def print_success(msg):
    print(f"{Colors.GREEN}[✓]{Colors.RESET} {msg}")

def print_warning(msg):
    print(f"{Colors.YELLOW}[!]{Colors.RESET} {msg}")

def print_error(msg):
    print(f"{Colors.RED}[✗]{Colors.RESET} {msg}")

def print_finding(severity, title, details):
    colors = {
        'HIGH': Colors.RED,
        'MEDIUM': Colors.YELLOW,
        'LOW': Colors.CYAN,
        'INFO': Colors.BLUE
    }
    color = colors.get(severity, Colors.RESET)
    print(f"\n{color}[{severity}]{Colors.RESET} {Colors.BOLD}{title}{Colors.RESET}")
    print(f"    {details}")

# ============================================================
# SECURITY PATTERNS
# ============================================================

PATTERNS = {
    'secrets': {
        'AWS Access Key': r'AKIA[0-9A-Z]{16}',
        'AWS Secret Key': r'aws_secret[_\-]?key[\s:=]+["\']?([A-Za-z0-9/+=]{40})',
        'API Key': r'api[_\-]?key[\s:=]+["\']?([A-Za-z0-9_\-]{20,})',
        'Auth Token': r'auth[_\-]?token[\s:=]+["\']?([A-Za-z0-9_\-]{20,})',
        'Bearer Token': r'Bearer\s+([A-Za-z0-9\-._~+/]+=*)',
        'Private Key': r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----',
        'Password': r'password[\s:=]+["\']([^"\']{8,})["\']',
        'Secret': r'secret[\s:=]+["\']?([A-Za-z0-9_\-]{20,})',
        'GitHub Token': r'gh[pousr]_[A-Za-z0-9]{36}',
        'Slack Token': r'xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[A-Za-z0-9]{24,}',
        'Google API': r'AIza[0-9A-Za-z\-_]{35}',
        'Database URL': r'(?:mysql|postgres|mongodb):\/\/[^\s]+',
    },
    'endpoints': {
        'API Endpoint': r'(?:https?:)?\/\/[a-zA-Z0-9\-\.]+\/api\/[^\s\'"<>]+',
        'GraphQL': r'(?:https?:)?\/\/[a-zA-Z0-9\-\.]+\/graphql',
        'Admin Panel': r'(?:https?:)?\/\/[a-zA-Z0-9\-\.]+\/(?:admin|dashboard|manage)',
        'Internal URL': r'(?:https?:)?\/\/(?:localhost|127\.0\.0\.1|192\.168\.[0-9]{1,3}\.[0-9]{1,3}|10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})',
    },
    'dom_xss': {
        'location.hash sink': r'location\.hash',
        'location.search sink': r'location\.search',
        'document.URL sink': r'document\.URL',
        'innerHTML sink': r'\.innerHTML\s*=',
        'eval() sink': r'eval\s*\(',
        'document.write sink': r'document\.write\s*\(',
        'window.name sink': r'window\.name',
    },
    'interesting': {
        'Email Address': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        'S3 Bucket': r'[a-z0-9.-]+\.s3\.amazonaws\.com|s3://[a-z0-9.-]+',
        'Firebase URL': r'[a-z0-9.-]+\.firebaseio\.com',
        'Subdomain': r'(?:https?:)?\/\/([a-z0-9]+(?:[.-][a-z0-9]+)*)\.[a-z]{2,}',
        'Comment TODO': r'(?:TODO|FIXME|HACK|XXX|BUG)[\s:]+(.{0,100})',
    }
}

# ============================================================
# JS FILE DOWNLOADER
# ============================================================

async def download_js(session, url, output_dir):
    """Download a single JS file"""
    try:
        parsed = urlparse(url)
        filename = parsed.path.split('/')[-1] or 'index.js'
        if not filename.endswith('.js'):
            filename += '.js'
        
        # Sanitize filename
        filename = re.sub(r'[^\w\-.]', '_', filename)
        filepath = output_dir / filename
        
        async with session.get(url, timeout=30, ssl=False) as response:
            if response.status == 200:
                content = await response.text()
                filepath.write_text(content, encoding='utf-8', errors='ignore')
                return url, content, filename, None
            else:
                return url, None, filename, f"HTTP {response.status}"
    except Exception as e:
        return url, None, filename, str(e)

async def download_all_js(urls, output_dir):
    """Download all JS files concurrently"""
    print_info(f"Downloading {len(urls)} JS files...")
    
    connector = aiohttp.TCPConnector(limit=10, ssl=False)
    timeout = aiohttp.ClientTimeout(total=60)
    
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        tasks = [download_js(session, url.strip(), output_dir) for url in urls]
        results = []
        
        for coro in asyncio.as_completed(tasks):
            result = await coro
            results.append(result)
            url, content, filename, error = result
            if content:
                print_success(f"Downloaded: {filename}")
            else:
                print_warning(f"Failed: {filename} - {error}")
    
    return results

# ============================================================
# SECURITY SCANNER
# ============================================================

def scan_content(content, patterns):
    """Scan content for security issues"""
    findings = {}
    
    for category, category_patterns in patterns.items():
        findings[category] = {}
        for name, pattern in category_patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                # Deduplicate and limit matches
                unique_matches = list(set(matches))[:10]
                findings[category][name] = unique_matches
    
    return findings

def calculate_severity(category, pattern_name):
    """Calculate severity of finding"""
    if category == 'secrets':
        if any(x in pattern_name.lower() for x in ['private key', 'aws', 'password']):
            return 'HIGH'
        return 'MEDIUM'
    elif category == 'dom_xss':
        return 'MEDIUM'
    elif category == 'endpoints' and 'admin' in pattern_name.lower():
        return 'MEDIUM'
    else:
        return 'INFO'

# ============================================================
# REPORT GENERATION
# ============================================================

def generate_text_report(all_findings, output_dir):
    """Generate clean text report"""
    report_file = output_dir / "SECURITY_REPORT.txt"
    
    with open(report_file, 'w') as f:
        f.write("="*70 + "\n")
        f.write("JS SECURITY SCAN REPORT\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("="*70 + "\n\n")
        
        # Summary
        total_files = len(all_findings)
        total_issues = sum(
            len(findings[cat]) 
            for findings in all_findings.values() 
            for cat in findings
        )
        
        f.write("SUMMARY\n")
        f.write("-" * 70 + "\n")
        f.write(f"Total JS Files Scanned: {total_files}\n")
        f.write(f"Total Issues Found: {total_issues}\n\n")
        
        # Count by severity
        severity_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for filename, findings in all_findings.items():
            for category, items in findings.items():
                for pattern_name, matches in items.items():
                    severity = calculate_severity(category, pattern_name)
                    severity_counts[severity] += len(matches)
        
        f.write(f"  🔴 HIGH:   {severity_counts['HIGH']}\n")
        f.write(f"  🟡 MEDIUM: {severity_counts['MEDIUM']}\n")
        f.write(f"  🔵 LOW:    {severity_counts['LOW']}\n")
        f.write(f"  ℹ️  INFO:   {severity_counts['INFO']}\n\n")
        
        # Detailed findings by file
        f.write("\n" + "="*70 + "\n")
        f.write("DETAILED FINDINGS\n")
        f.write("="*70 + "\n\n")
        
        for filename, findings in all_findings.items():
            has_findings = any(findings[cat] for cat in findings)
            if not has_findings:
                continue
                
            f.write(f"\n📄 FILE: {filename}\n")
            f.write("-" * 70 + "\n")
            
            for category, items in findings.items():
                if not items:
                    continue
                    
                f.write(f"\n  [{category.upper()}]\n")
                for pattern_name, matches in items.items():
                    severity = calculate_severity(category, pattern_name)
                    f.write(f"    [{severity}] {pattern_name}:\n")
                    for match in matches[:5]:  # Limit to 5 per type
                        # Truncate long matches
                        match_str = str(match)[:100]
                        f.write(f"      • {match_str}\n")
                    if len(matches) > 5:
                        f.write(f"      ... and {len(matches)-5} more\n")
                f.write("\n")
    
    print_success(f"Text report saved: {report_file}")
    return report_file

def generate_html_report(all_findings, output_dir):
    """Generate HTML report"""
    report_file = output_dir / "SECURITY_REPORT.html"
    
    # Count by severity
    severity_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
    for filename, findings in all_findings.items():
        for category, items in findings.items():
            for pattern_name, matches in items.items():
                severity = calculate_severity(category, pattern_name)
                severity_counts[severity] += len(matches)
    
    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>JS Security Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: 'Segoe UI', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }}
        .container {{ 
            max-width: 1200px; 
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        .header {{ 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        .header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .header p {{ opacity: 0.9; font-size: 1.1em; }}
        .summary {{ 
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 40px;
            background: #f8f9fa;
        }}
        .stat-card {{
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.07);
            text-align: center;
            transition: transform 0.3s;
        }}
        .stat-card:hover {{ transform: translateY(-5px); }}
        .stat-card .number {{ 
            font-size: 2.5em; 
            font-weight: bold; 
            margin: 10px 0;
        }}
        .stat-card .label {{ 
            color: #666; 
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .high {{ color: #dc3545; }}
        .medium {{ color: #ffc107; }}
        .low {{ color: #17a2b8; }}
        .info {{ color: #6c757d; }}
        .content {{ padding: 40px; }}
        .file-section {{
            margin-bottom: 40px;
            border: 1px solid #e0e0e0;
            border-radius: 10px;
            overflow: hidden;
        }}
        .file-header {{
            background: #667eea;
            color: white;
            padding: 20px;
            font-weight: bold;
            font-size: 1.2em;
        }}
        .file-body {{ padding: 20px; }}
        .category {{
            margin-bottom: 25px;
        }}
        .category-title {{
            font-size: 1.1em;
            font-weight: bold;
            color: #667eea;
            margin-bottom: 10px;
            padding-bottom: 5px;
            border-bottom: 2px solid #667eea;
        }}
        .finding {{
            background: #f8f9fa;
            padding: 15px;
            margin: 10px 0;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }}
        .finding-title {{
            font-weight: bold;
            margin-bottom: 8px;
        }}
        .finding-match {{
            background: #e9ecef;
            padding: 8px 12px;
            margin: 5px 0;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            word-break: break-all;
        }}
        .severity-badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
            margin-right: 10px;
        }}
        .severity-high {{ background: #dc3545; color: white; }}
        .severity-medium {{ background: #ffc107; color: #333; }}
        .severity-low {{ background: #17a2b8; color: white; }}
        .severity-info {{ background: #6c757d; color: white; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 JavaScript Security Report</h1>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="summary">
            <div class="stat-card">
                <div class="label">Files Scanned</div>
                <div class="number">{len(all_findings)}</div>
            </div>
            <div class="stat-card">
                <div class="number high">{severity_counts['HIGH']}</div>
                <div class="label">High Severity</div>
            </div>
            <div class="stat-card">
                <div class="number medium">{severity_counts['MEDIUM']}</div>
                <div class="label">Medium Severity</div>
            </div>
            <div class="stat-card">
                <div class="number info">{severity_counts['INFO']}</div>
                <div class="label">Informational</div>
            </div>
        </div>
        
        <div class="content">
            <h2 style="margin-bottom: 30px; color: #667eea;">📋 Detailed Findings</h2>
"""
    
    for filename, findings in all_findings.items():
        has_findings = any(findings[cat] for cat in findings)
        if not has_findings:
            continue
        
        html += f"""
            <div class="file-section">
                <div class="file-header">📄 {filename}</div>
                <div class="file-body">
"""
        
        for category, items in findings.items():
            if not items:
                continue
            
            html += f'<div class="category"><div class="category-title">{category.upper().replace("_", " ")}</div>'
            
            for pattern_name, matches in items.items():
                severity = calculate_severity(category, pattern_name)
                severity_class = severity.lower()
                
                html += f"""
                    <div class="finding">
                        <div class="finding-title">
                            <span class="severity-badge severity-{severity_class}">{severity}</span>
                            {pattern_name}
                        </div>
"""
                for match in matches[:5]:
                    match_str = str(match)[:150]
                    html += f'<div class="finding-match">{match_str}</div>'
                
                if len(matches) > 5:
                    html += f'<div style="margin-top: 10px; color: #666; font-style: italic;">... and {len(matches)-5} more occurrences</div>'
                
                html += '</div>'
            
            html += '</div>'
        
        html += '</div></div>'
    
    html += """
        </div>
    </div>
</body>
</html>
"""
    
    report_file.write_text(html, encoding='utf-8')
    print_success(f"HTML report saved: {report_file}")
    return report_file

# ============================================================
# MAIN
# ============================================================

async def main():
    print_banner()
    
    # Check if js_files.txt exists
    input_file = Path("js_files.txt")
    if not input_file.exists():
        print_error("js_files.txt not found!")
        print_info("Create js_files.txt with one JS URL per line")
        sys.exit(1)
    
    # Read URLs
    urls = [line.strip() for line in input_file.read_text().splitlines() if line.strip()]
    if not urls:
        print_error("No URLs found in js_files.txt")
        sys.exit(1)
    
    print_info(f"Found {len(urls)} JS URLs to scan")
    
    # Create output directory
    output_dir = Path("js_scan_results")
    output_dir.mkdir(exist_ok=True)
    js_dir = output_dir / "js_files"
    js_dir.mkdir(exist_ok=True)
    
    # Download JS files
    results = await download_all_js(urls, js_dir)
    
    # Scan files
    print_info("\nScanning for security issues...")
    all_findings = {}
    
    for url, content, filename, error in results:
        if content:
            findings = scan_content(content, PATTERNS)
            all_findings[filename] = findings
            
            # Print summary for this file
            total_in_file = sum(len(items) for cat in findings.values() for items in cat.values())
            if total_in_file > 0:
                print_warning(f"{filename}: {total_in_file} issues found")
    
    # Generate reports
    print_info("\nGenerating reports...")
    generate_text_report(all_findings, output_dir)
    generate_html_report(all_findings, output_dir)
    
    # Final summary
    print("\n" + "="*70)
    print_success("Scan completed!")
    print_info(f"Results saved in: {output_dir}/")
    print_info("  • SECURITY_REPORT.txt (text version)")
    print_info("  • SECURITY_REPORT.html (open in browser)")
    print_info("  • js_files/ (downloaded JS files)")
    print("="*70 + "\n")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print_warning("\n\nScan interrupted by user")
        sys.exit(0)
