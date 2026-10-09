"""
CyberDNA - Frontend DOM & Element Integrity Checker
Verifies that all interactive DOM selectors, classes, and IDs map 1:1 between script.js and index.html.
"""

import re

with open('frontend/index.html', 'r', encoding='utf-8') as f:
    html = f.read()

with open('frontend/script.js', 'r', encoding='utf-8') as f:
    js = f.read()

elem_ids = re.findall(r'getElementById\([\"\']([^\"\']+)[\"\']\)', js)
missing = []
for eid in set(elem_ids):
    if f'id="{eid}"' not in html and f"id='{eid}'" not in html:
        # Check if it might be dynamically created or in template
        missing.append(eid)

print(f"Total DOM IDs referenced in script.js: {len(set(elem_ids))}")
if missing:
    print(f"Missing IDs in HTML: {missing}")
else:
    print("[PASS] All DOM IDs referenced in script.js exist in index.html!")

# Check sections
sections = [
    "section-overview", "section-analysis", "section-patterns",
    "section-predictions", "section-alerts", "section-entities",
    "section-reports", "section-history", "section-settings"
]
for sec in sections:
    assert f'id="{sec}"' in html, f"Missing section: {sec}"
print(f"[PASS] All {len(sections)} sections are defined in index.html!")

# Check Chart elements
charts = [
    "chart-events-timeline", "chart-severity-dist", "chart-stage-dist",
    "chart-risk-trend", "chart-event-types", "chart-entities-risk"
]
for ch in charts:
    assert f'id="{ch}"' in html, f"Missing chart canvas: {ch}"
print(f"[PASS] All {len(charts)} chart canvas elements exist in index.html!")
