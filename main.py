import subprocess

# Kör risk_tool.py och exportera alltid till CSV
subprocess.run([
    "python", "risk_tool.py", "HomeSystem_Threats.json",
    "--tree", "attack_tree_data.json",
    "--simulate", "10000",
    "--csv", "threats.csv"
])

# Kör attack_tree.py (visualisering av attackträdet)
subprocess.run(["python", "attack_tree_homesystem.py"])