# ThreatModelling_SystemRiskProfiling
Foundations of Cybersecurity, Threat Modeling, and System Risk Profiling

## Viewing .drawio Files in VS Code

To view and edit `.drawio` files (like `DFD.drawio`) directly in Visual Studio Code:

1. **Install the Draw.io Integration Extension:**
   - Go to the Extensions view (`Ctrl+Shift+X`).
   - Search for `Draw.io Integration` or `drawio`.
   - Click **Install** on the extension.

2. **Open Your .drawio File:**
   - After installing, open your `.drawio` file.
   - It will display the diagram visually, and you can edit it within VS Code.

This allows you to work with diagrams without leaving your

---

## Description of JSON Files

### smarttv_threats.json

This file contains a detailed threat analysis for a Smart TV system. Each object in the list represents a specific security threat (e.g., MITM attacks, stolen authentication tokens, weak update routines) and is structured according to two established frameworks:

- **STRIDE**: Classifies threats based on six categories (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege).
- **DREAD**: Provides a risk assessment for each threat based on factors such as damage, reproducibility, exploitability, affected users, and discoverability.

Each threat also includes a description, probability estimate, and suggested mitigations. The file is used to identify, prioritize, and manage security risks in the system.

### attack_tree.json

This file describes an attack tree for the Smart TV system. An attack tree visualizes different paths an attacker can take to compromise the system. The tree has a root goal ("Compromise Smart TV") and shows which combinations of threats (referenced by their IDs from `smarttv_threats.json`) can lead to achieving that goal.

- **OR/AND logic**: The tree uses logical operators to show whether a single threat is sufficient (OR) or if multiple threats must be combined (AND) for a successful attack.
- **Example**: An attacker can compromise the TV by succeeding with T2, T1, or both T3 and T6 together.


The attack tree helps to understand and analyze how different threats interact and which attack paths are most critical to defend against.