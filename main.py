import subprocess

# Kör risk_tool.py och exportera alltid till CSV
subprocess.run([
    "python", "risk_tool.py", "smarttv_threats.json",
    "--tree", "attack_tree.json",
    "--simulate", "10000",
    "--csv", "threats.csv"
])

# Kör attack_three.py (visualisering av attackträdet)
subprocess.run(["python", "attack_three.py"])