import argparse
import json
import csv
import random
from typing import List, Dict, Any, Optional

def load_threats(filepath: str) -> List[Dict[str, Any]]:
    """
    Load threats from a JSON or YAML file.
    """
    with open(filepath, "r", encoding="utf-8") as file:
        content = file.read()
    try:
        return json.loads(content)
    except Exception:
        try:
            import yaml
            return yaml.safe_load(content)
        except Exception as e:
            raise SystemExit(f"Failed to parse {filepath} as JSON or YAML: {e}")

def calculate_dread_score(dread: Dict[str, float]) -> float:
    """
    Calculate the DREAD score for a threat.
    """
    keys = ["damage", "reproducibility", "exploitability", "affected_users", "discoverability"]
    values = [float(dread.get(k, 0)) for k in keys]
    return sum(values) / len(values) if values else 0.0

def determine_severity(score: float) -> str:
    """
    Determine severity level based on DREAD score.
    """
    if score >= 8:
        return "Critical"
    if score >= 6.5:
        return "High"
    if score >= 5:
        return "Medium"
    if score > 0:
        return "Low"
    return "None"

def enrich_threats(threats: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Attach DREAD score and severity to each threat.
    """
    for threat in threats:
        dread = threat.get("dread", {})
        threat["score"] = calculate_dread_score(dread)
        threat["severity"] = determine_severity(threat["score"])
    return threats

def print_threat_report(threats: List[Dict[str, Any]], sort_key: str = "score") -> None:
    """
    Print a ranked report of threats to the console.
    """
    print("\n=== Ranked Threats (by DREAD score) ===")
    print(f"{'Rank':<5} {'ID':<6} {'Score':>5}  {'Severity':<9}  {'STRIDE':<28}  Description")
    print("-" * 100)
    sorted_threats = sorted(threats, key=lambda x: (-x.get(sort_key, 0), x.get('id', '')))
    for i, t in enumerate(sorted_threats, start=1):
        stride = ",".join(t.get("stride", []))
        print(f"{i:<5} {t.get('id',''):<6} {t['score']:5.2f}  {t['severity']:<9}  {stride:<28}  {t.get('description','')}")
    print()

def export_threats_csv(threats: List[Dict[str, Any]], filepath: str) -> None:
    """
    Export the ranked threats to a CSV file.
    """
    fieldnames = ["rank", "id", "score", "severity", "stride", "location", "description", "mitigations", "prob"]
    sorted_threats = sorted(threats, key=lambda x: (-x.get("score", 0), x.get("id", "")))
    with open(filepath, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        for i, t in enumerate(sorted_threats, start=1):
            writer.writerow({
                "rank": i,
                "id": t.get("id", ""),
                "score": f"{t['score']:.2f}",
                "severity": t["severity"],
                "stride": "|".join(t.get("stride", [])),
                "location": t.get("location", ""),
                "description": t.get("description", ""),
                "mitigations": "; ".join(t.get("mitigations", [])),
                "prob": t.get("prob", "")
            })

def export_threats_markdown(threats: List[Dict[str, Any]], filepath: str) -> None:
    """
    Export the ranked threats to a Markdown file.
    """
    lines = [
        "# Ranked Threats\n",
        "| Rank | ID | Score | Severity | STRIDE | Location | Description | Mitigations | Prob |",
        "|---:|:--:|--:|:--:|:--|:--|:--|:--|--:|"
    ]
    sorted_threats = sorted(threats, key=lambda x: (-x.get("score", 0), x.get("id", "")))
    for i, t in enumerate(sorted_threats, start=1):
        lines.append(
            f"| {i} | {t.get('id','')} | {t['score']:.2f} | {t['severity']} | {'/'.join(t.get('stride', []))} | "
            f"{t.get('location','')} | {t.get('description','')} | {'; '.join(t.get('mitigations', []))} | {t.get('prob','')} |"
        )
    with open(filepath, "w", encoding="utf-8") as file:
        file.write("\n".join(lines))

def evaluate_attack_tree(node: Dict[str, Any], threat_index: Dict[str, Dict[str, Any]]) -> float:
    """
    Recursively evaluate the probability of success for an attack tree node.
    """
    if node is None:
        return 0.0
    if "ref" in node:
        threat = threat_index.get(node["ref"])
        return float(threat.get("prob", 0.0)) if threat else 0.0
    logic = node.get("logic", "OR").upper()
    children = node.get("children", [])
    probabilities = [evaluate_attack_tree(child, threat_index) for child in children]
    if not probabilities:
        return 0.0
    if logic == "AND":
        result = 1.0
        for p in probabilities:
            result *= p
        return result
    else:  # OR
        result = 1.0
        for p in probabilities:
            result *= (1.0 - p)
        return 1.0 - result

def monte_carlo_compromise_probability(threats: List[Dict[str, Any]], iterations: int = 10000) -> (float, float):
    """
    Calculate overall compromise probability using analytic formula and Monte Carlo simulation.
    """
    probabilities = [float(t.get("prob", 0.0)) for t in threats if t.get("prob") is not None]
    analytic = 1.0 - prod(1.0 - p for p in probabilities)
    successes = 0
    for _ in range(iterations):
        if any(random.random() < p for p in probabilities):
            successes += 1
    monte_carlo = successes / iterations if iterations > 0 else analytic
    return analytic, monte_carlo

def prod(iterable):
    """
    Return the product of a sequence of numbers.
    """
    result = 1.0
    for x in iterable:
        result *= x
    return result

def main():
    parser = argparse.ArgumentParser(description="IoT Threat Modeling Risk Tool (Smart TV Example)")
    parser.add_argument("input", nargs="?", default="smarttv_threats.json",
                        help="Threats file (JSON or YAML). Default: smarttv_threats.json")
    parser.add_argument("--csv", help="Export ranked threats to CSV")
    parser.add_argument("--md", help="Export ranked threats to Markdown")
    parser.add_argument("--simulate", type=int, default=0, help="Run Monte Carlo with N iterations (uses per-threat 'prob')")
    parser.add_argument("--tree", help="Attack tree JSON file (optional)")
    args = parser.parse_args()

    threats = load_threats(args.input)
    enrich_threats(threats)
    print_threat_report(threats)

    if args.csv:
        export_threats_csv(threats, args.csv)
        print(f"CSV exported to {args.csv}")
    if args.md:
        export_threats_markdown(threats, args.md)
        print(f"Markdown exported to {args.md}")

    if args.simulate:
        analytic, monte_carlo = monte_carlo_compromise_probability(threats, iterations=args.simulate)
        print(f"Overall compromise probability (independent threats): analytic={analytic:.3f}, MonteCarlo({args.simulate})={monte_carlo:.3f}")

    if args.tree:
        with open(args.tree, "r", encoding="utf-8") as file:
            tree = json.load(file)
        threat_index = {t["id"]: t for t in threats}
        tree_probability = evaluate_attack_tree(tree, threat_index)
        print(f"Attack tree root '{tree.get('root', 'root')}' success probability (analytic): {tree_probability:.3f}")

if __name__ == '__main__':
    main()
# EOF
