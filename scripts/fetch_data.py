import requests
import json
import datetime
import os

# --- CONFIGURATION ---
CISA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OUTPUT_DIR = "public"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "index.html")

# MSP Filter: Exclude consumer noise
EXCLUDED_KEYWORDS = ['xbox', 'kinect', 'hololens', 'surface duo', 'dynamics nav', 'zune', 'phone']

# High Priority: Highlight Core Infra & Identity
MSP_CRITICAL_KEYWORDS = [
    'server', 'exchange', 'sharepoint', 'entra', 'active directory', 
    'domain controller', 'intune', 'defender', 'rdp', 'remote desktop', 'elevation of privilege'
]

# Static EOL Data (The "Big Ticket" items for MSPs)
EOL_DATA = [
    {"product": "Windows 10", "eol": "2025-10-14", "status": "warning"},
    {"product": "Windows Server 2012 / R2", "eol": "2023-10-10", "status": "critical"},
    {"product": "Exchange Server 2016", "eol": "2025-10-14", "status": "warning"},
    {"product": "Office 2016 / 2019", "eol": "2025-10-14", "status": "warning"},
    {"product": "Windows Server 2016", "eol": "2027-01-12", "status": "ok"},
]

def fetch_cisa_kev():
    try:
        r = requests.get(CISA_URL)
        r.raise_for_status()
        data = r.json()
        
        msp_vulns = []
        for v in data.get('vulnerabilities', []):
            vendor = v.get('vendorProject', '').lower()
            product = v.get('product', '').lower()
            
            if 'microsoft' not in vendor: continue
            if any(k in product for k in EXCLUDED_KEYWORDS): continue
                
            v['is_critical_infra'] = any(k in product or k in v.get('vulnerabilityName', '').lower() for k in MSP_CRITICAL_KEYWORDS)
            msp_vulns.append(v)
            
        return sorted(msp_vulns, key=lambda x: x['dateAdded'], reverse=True)[:50]
    except Exception as e:
        print(f"Error: {e}")
        return []

def generate_html(vulns):
    css = """
        body { font-family: 'Segoe UI', sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; background: #f4f4f9; color: #333; }
        h1, h2 { border-bottom: 2px solid #0078d4; padding-bottom: 10px; color: #0078d4; }
        .section { margin-bottom: 40px; }
        
        /* EOL Table */
        table { width: 100%; border-collapse: collapse; background: white; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #eee; }
        th { background: #f8f9fa; font-weight: 600; }
        .status-critical { color: #d13438; font-weight: bold; }
        .status-warning { color: #a4262c; }
        .status-ok { color: #107c10; }

        /* Vuln Cards */
        .card { background: white; padding: 20px; margin-bottom: 15px; border-left: 5px solid #ccc; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .card.critical { border-left-color: #d13438; }
        .tag { background: #e1dfdd; padding: 2px 6px; border-radius: 4px; font-size: 0.85rem; margin-right: 10px; }
        .msp-badge { background: #d13438; color: white; font-weight: bold; }
    """

    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head><meta charset="UTF-8"><title>MSP Threat Watch</title><style>{css}</style></head>
    <body>
        <div style="display:flex; justify-content:space-between; align-items:center;">
            <h1>Managed Workspace Threat Watch</h1>
            <small>Updated: {datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")}</small>
        </div>

        <div class="section">
            <h2>Upcoming End-of-Life (Major)</h2>
            <table>
                <tr><th>Product</th><th>EOL Date</th><th>Status</th></tr>
                {''.join([f"<tr><td>{i['product']}</td><td>{i['eol']}</td><td class='status-{i['status']}'>{i['status'].upper()}</td></tr>" for i in EOL_DATA])}
            </table>
        </div>

        <div class="section">
            <h2>Active Exploitations (CISA KEV)</h2>
            {'<p>No active threats found.</p>' if not vulns else ''}
    """
    
    for v in vulns:
        badge = '<span class="tag msp-badge">CRITICAL INFRA</span>' if v.get('is_critical_infra') else ''
        cls = 'critical' if v.get('is_critical_infra') else ''
        html += f"""
        <div class="card {cls}">
            <h3>{v.get('product')} {badge}</h3>
            <p><strong>{v.get('cveID')}</strong>: {v.get('shortDescription')}</p>
            <div style="margin-top:10px; font-size:0.9rem; color:#666;">
                <span class="tag">Added: {v.get('dateAdded')}</span>
                <strong>Action:</strong> {v.get('requiredAction')}
            </div>
        </div>
        """
    
    html += "</div></body></html>"
    return html

if __name__ == "__main__":
    if not os.path.exists(OUTPUT_DIR): os.makedirs(OUTPUT_DIR)
    vulns = fetch_cisa_kev()
    with open(OUTPUT_FILE, 'w') as f: f.write(generate_html(vulns))
