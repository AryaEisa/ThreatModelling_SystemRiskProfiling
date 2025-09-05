# ThreatModelling_SystemRiskProfiling

Foundations of Cybersecurity: Threat Modeling and System Risk Profiling

---

## Project Overview

This repository demonstrates a structured approach to threat modeling for a fictional IoT system (Smart TV). The solution applies industry-standard frameworks (STRIDE, DREAD, CIA triad), visualizes attack paths, and provides a Python tool for risk analysis and simulation.

---

## File Structure

| File                        | Description                                                                                   |
|-----------------------------|----------------------------------------------------------------------------------------------|
| `ThreatModelDiagram.drawio` | Data Flow Diagram (DFD) and STRIDE threat table for the Smart TV system                      |
| `smarttv_threats.json`      | List of identified threats, each classified and scored using STRIDE and DREAD                |
| `attack_tree.json`          | Attack tree describing how threats can be combined to compromise the Smart TV                |
| `risk_tool.py`              | Python tool for risk ranking, simulation, and attack tree evaluation                         |
| `attack_three.py`           | Visualizes the attack tree as a hierarchical, layered diagram and saves it as an image       |
| `main.py`                   | Runs both risk analysis and attack tree visualization scripts in sequence                    |
| `attack_tree.png`           | Example output image of the attack tree visualization                                        |
| `README.md`                 | Project documentation and instructions                                                       |

---

## Viewing Diagrams in Visual Studio Code

To view and edit `.drawio` files (such as `ThreatModelDiagram.drawio`) directly in Visual Studio Code:

1. Open the Extensions view (`Ctrl+Shift+X`).
2. Search for and install the "Draw.io Integration" extension.
3. Open your `.drawio` file to view and edit diagrams within VS Code.

---

## System Scope

### Key Assets

- Smart TV device (hardware and firmware)
- User credentials and authentication tokens
- User data (settings, preferences, viewing history)
- Network connection (WiFi/Ethernet)
- Cloud services (OAuth/IDP, firmware update servers)

### Attacker Profiles

- **External attacker:** Attempts attacks via the internet (e.g., MITM, remote exploitation).
- **Internal attacker:** Has physical access to the home network or TV (e.g., household member, guest).

### Trust Boundaries

- Home network ↔ Internet: Traffic between the home network and external services.
- Smart TV ↔ Local storage: Protection of stored credentials and sensitive data.
- Smart TV ↔ Cloud services: Authentication and secure communication with external services.

### Entry and Exit Points

- Network interfaces (WiFi/Ethernet)
- Remote control interfaces (IR/Bluetooth)
- Firmware update mechanism (internet-based updates)
- Application interfaces (apps running on the TV)

### Data Flows

- User input to Smart TV (remote control, app)
- Smart TV to/from cloud services (authentication, updates, data retrieval)
- Smart TV to/from local storage (tokens, settings)
- Smart TV to/from the internet (streaming, third-party services)

---

## Threat Modeling Approach

- **STRIDE:** Each threat in `smarttv_threats.json` is classified according to the STRIDE model (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege).
- **DREAD:** Each threat is scored using the DREAD model (damage, reproducibility, exploitability, affected users, discoverability).
- **CIA Triad:** The model addresses Confidentiality, Integrity, and Availability through STRIDE/DREAD categories.

---

## Threat and Attack Tree Files

### smarttv_threats.json

- Contains a list of threats relevant to the Smart TV system.
- Each threat includes:
  - Unique ID
  - Location in the system
  - Description
  - STRIDE classification
  - DREAD risk assessment
  - Probability estimate
  - Suggested mitigations

### attack_tree.json

- Describes an attack tree using a hierarchical, logical structure (AND/OR nodes).
- Each node can reference a threat by its unique ID, and leaf nodes correspond to specific threats from `smarttv_threats.json`.
- Logical nodes (AND/OR) define how multiple threats must combine for a successful attack (e.g., all must occur for AND, any for OR).
- Each threat node includes a probability, which is used for analytic and simulation-based risk calculations.
- The root node represents the overall compromise of the Smart TV and sits at the top of the tree.
- The attack tree can be visualized as a layered, top-down diagram using the provided Python script, making the logical structure and dependencies clear.
- Used to analyze how different threats can combine to achieve a successful attack, and to compute the probability of system compromise via analytic or Monte Carlo methods.

---

## Python Risk Tool (`risk_tool.py`)

- Reads threats from JSON or YAML files.
- Calculates DREAD scores and STRIDE tags for each threat.
- Ranks threats and generates reports (console, CSV, Markdown).
- Supports Monte Carlo simulation to estimate the probability of system compromise.
- Evaluates attack trees to determine the likelihood of a successful attack path.

### Example Usage

```sh
python risk_tool.py smarttv_threats.json
python risk_tool.py smarttv_threats.json --csv threats.csv --md threats.md
python risk_tool.py smarttv_threats.json --simulate 10000
python risk_tool.py smarttv_threats.json --tree attack_tree.json
```

---

## Attack Tree Visualization (`attack_three.py`)

- Visualizes the attack tree (`attack_tree.json`) as a hierarchical, layered diagram using NetworkX and Matplotlib.
- Uses a top-down layout to clearly show the logical structure (AND/OR nodes) and threat dependencies.
- Colors and shapes distinguish between logic nodes and threat nodes.
- The resulting attack tree visualization is automatically saved as `attack_tree.png` in the project directory.
- You can view the generated image directly or include it in reports.

---

## Main Script (`main.py`)

- Runs both `risk_tool.py` (for risk analysis, simulation, and attack tree evaluation) and `attack_three.py` (for attack tree visualization) in sequence.
- **To generate all analysis and visual outputs with a single command, run:**

```sh
python main.py
```

- This will produce console reports, simulation results, the attack tree image, and always export the threats as a CSV file (`threats.csv`) in the project directory.

---

## Example Output

You can use the generated `attack_tree.png` as a visual summary of the attack tree structure in your documentation or presentations.

---

## Summary

This project provides a complete workflow for structured threat modeling of an IoT system, including:

- Asset and attacker analysis
- Trust boundary and data flow identification
- STRIDE/DREAD-based threat documentation
- Attack tree construction and evaluation
- Automated risk ranking and simulation

The approach and tools can be adapted to other IoT or cyber-physical systems for comprehensive threat modeling and risk assessment.