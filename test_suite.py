"""
CyberDNA - Automated End-to-End System Test Suite
Verifies all core capabilities, target scanner validation, and dynamic updates.
"""

import urllib.request
import urllib.error
import json
import os
from backend.database import clear_database

base_url = 'http://127.0.0.1:5000'

def run_tests():
    print("=" * 60)
    print("  CYBERDNA AUTOMATED TEST SUITE")
    print("=" * 60)

    # Reset to pristine clean state
    clear_database()

    # 1. Test index page loads
    req = urllib.request.urlopen(f'{base_url}/')
    assert req.status == 200
    html = req.read().decode('utf-8')
    assert 'CYBERDNA' in html
    assert 'Enter Target' in html
    assert 'Start Scan' in html
    print("[PASS] 1. Home page loads with status 200, Target Input, and 'Start Scan' button")

    # 2. Test initial dashboard empty state (No fake data)
    req = urllib.request.urlopen(f'{base_url}/api/dashboard')
    dash = json.loads(req.read().decode('utf-8'))
    assert dash['success'] is True
    assert dash['has_data'] is False
    assert dash['data'] is None
    print("[PASS] 2. Dashboard starts cleanly with zero fake/mock scan results (has_data=False)")

    # 3. Test Target Input Validation: Empty target
    req_empty = urllib.request.Request(
        f'{base_url}/api/scan',
        data=json.dumps({'target': ''}).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )
    try:
        urllib.request.urlopen(req_empty)
        assert False, "Empty target should return error"
    except urllib.error.HTTPError as e:
        assert e.code == 400
        res = json.loads(e.read().decode('utf-8'))
        assert res['success'] is False
        print(f"[PASS] 3. Empty target validated and rejected: {res['error']}")

    # 4. Test Target Input Validation: Invalid syntax
    req_invalid = urllib.request.Request(
        f'{base_url}/api/scan',
        data=json.dumps({'target': 'bad@@target'}).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )
    try:
        urllib.request.urlopen(req_invalid)
        assert False, "Invalid target should return error"
    except urllib.error.HTTPError as e:
        assert e.code == 400
        res = json.loads(e.read().decode('utf-8'))
        assert res['success'] is False
        print(f"[PASS] 4. Invalid target syntax validated and rejected: {res['error']}")

    # 5. Test Real Target Vulnerability Scan (127.0.0.1)
    req_scan = urllib.request.Request(
        f'{base_url}/api/scan',
        data=json.dumps({'target': '127.0.0.1'}).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )
    res_scan = json.loads(urllib.request.urlopen(req_scan).read().decode('utf-8'))
    assert res_scan['success'] is True
    scan_data = res_scan['data']
    assert scan_data['target'] == '127.0.0.1'
    print(f"[PASS] 5. Real target scan executed for {scan_data['target']}:")
    print(f"       Resolved IP: {scan_data['resolved_ip']}")
    print(f"       Risk Score: {scan_data['risk_score']}/100 ({scan_data['risk_level']})")
    print(f"       Perimeter Findings: {len(scan_data['vulnerabilities'])} vulnerabilities")

    # 6. Test Dashboard reflects actual scanned target
    req_dash2 = urllib.request.urlopen(f'{base_url}/api/dashboard')
    dash2 = json.loads(req_dash2.read().decode('utf-8'))
    assert dash2['success'] is True
    assert dash2['has_data'] is True
    assert dash2['data']['target'] == '127.0.0.1'
    print(f"[PASS] 6. Dashboard dynamically populated with actual target scan: {dash2['data']['target']}")

    # 7. Test Alerts generated from live scan
    req = urllib.request.urlopen(f'{base_url}/api/alerts')
    alerts_data = json.loads(req.read().decode('utf-8'))
    assert alerts_data['success'] is True
    print(f"[PASS] 7. Alerts endpoint verified ({alerts_data['count']} alerts found)")

    # 8. Test Explainable AI reasons from live scan
    explanations = scan_data.get('explanation', [])
    assert len(explanations) > 0
    print(f"[PASS] 8. Explainable AI verified ({len(explanations)} evidence bullets extracted)")

    # 9. Test Report download (Markdown) from live scan
    active_id = scan_data['analysis_id']
    req = urllib.request.urlopen(f'{base_url}/api/reports/download/{active_id}?format=markdown')
    assert req.status == 200
    md = req.read().decode('utf-8')
    assert 'CYBERDNA DEFENSIVE SECURITY ASSESSMENT REPORT' in md
    print(f"[PASS] 9. Markdown report generated and downloadable (Reference: REP-{active_id})")

    # 10. Test 1-Click Defensive Remediation & Honeypot Playbook generated
    playbook = scan_data.get('remediation_playbook', {})
    assert 'nginx' in playbook, "Playbook should contain nginx"
    assert 'apache' in playbook, "Playbook should contain apache"
    assert 'cloudflare' in playbook, "Playbook should contain cloudflare"
    assert 'honeypot' in playbook, "Playbook should contain honeypot"
    assert 'decoy_id' in playbook, "Playbook should contain decoy_id"
    assert 'X-Debug-Canary-Gateway' in playbook['nginx']['snippet']
    assert playbook['decoy_id'] in playbook['nginx']['snippet']
    print(f"[PASS] 10. 1-Click Defensive Remediation & Honeypot Playbook verified (Decoy Token: {playbook['decoy_id']})")

    # 11. Test direct download of Nginx hardening configuration
    req_nginx = urllib.request.urlopen(f'{base_url}/api/remediation/download/{active_id}?server=nginx')
    assert req_nginx.status == 200
    nginx_conf = req_nginx.read().decode('utf-8')
    assert 'CYBERDNA DEFENSIVE REMEDIATION PLAYBOOK' in nginx_conf
    assert 'Strict-Transport-Security' in nginx_conf
    print(f"[PASS] 11. Nginx hardening config download verified (/api/remediation/download/{active_id}?server=nginx)")

    # 12. Test direct download of Honeypot canary configuration
    req_hp = urllib.request.urlopen(f'{base_url}/api/remediation/download/{active_id}?server=honeypot')
    assert req_hp.status == 200
    hp_conf = req_hp.read().decode('utf-8')
    assert 'CYBERDNA DECEPTION PLAYBOOK' in hp_conf
    assert playbook['decoy_id'] in hp_conf
    print(f"[PASS] 12. Honeypot decoy config download verified (/api/remediation/download/{active_id}?server=honeypot)")

    # 13. Test Markdown report contains Section 6 Defensive Hardening & Playbook
    req_md6 = urllib.request.urlopen(f'{base_url}/api/reports/download/{active_id}?format=markdown')
    assert req_md6.status == 200
    md_text = req_md6.read().decode('utf-8')
    assert '## 6. Defensive Remediation & Honeypot Playbook' in md_text
    assert playbook['decoy_id'] in md_text
    print(f"[PASS] 13. Markdown report Section 6 Defensive Playbook verified")

    # 14. Verify legacy CSV endpoints are properly disabled
    try:
        urllib.request.urlopen(f'{base_url}/api/sample-datasets')
        assert False, "Sample datasets should return 404"
    except urllib.error.HTTPError as e:
        assert e.code == 404
        print("[PASS] 14. Sample datasets endpoint properly disabled (404)")

    # Reset back to empty initial state for user
    clear_database()
    print("\n[INFO] Database reset to clean initial state for user interaction.")

    print("\n" + "=" * 60)
    print("  ALL 14 AUTOMATION TESTS PASSED WITH 100% SUCCESS!")
    print("=" * 60)

if __name__ == '__main__':
    run_tests()
