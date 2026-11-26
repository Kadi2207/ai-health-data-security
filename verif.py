import sys
sys.path.insert(0, "src")
from security_monitor import analyser_menaces, scan_complet
from datetime import datetime, timedelta

print("Heure actuelle système :", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
print("Fenêtre depuis :", (datetime.now() - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S"))
print()

menaces = analyser_menaces()
print(f"Menaces détectées : {len(menaces)}")
for m in menaces:
    print(f"  - {m['type']} / {m['utilisateur']} / {m['details']}")

print()
rapport = scan_complet()
print(f"Scan complet : {rapport['menaces_detectees']} menaces, {rapport['nouvelles_alertes']} nouvelles alertes")