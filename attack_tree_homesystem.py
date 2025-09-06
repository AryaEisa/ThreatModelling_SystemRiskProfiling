import json
import networkx as nx
import matplotlib.pyplot as plt
import pydot as pd
import textwrap

def build_threat_index(threats_path):
    """Load threats into a dictionary keyed by ID."""
    with open(threats_path, "r") as f:
        data = json.load(f)
    return {t["id"]: t for t in data if "id" in t}


def calculate_dread_score(d):
    return sum(d.values()) / 5.0

def determine_severity(score):
    if score >= 8: return "Critical"
    if score >= 6: return "High"
    if score >= 4: return "Medium"
    return "Low"

def visualize_attack_tree(threats_path, out_path):
    threat_index = build_threat_index(threats_path)

    G = nx.DiGraph()

    # Meta root
    meta_root = "Compromise Smart Home IoT System"
    G.add_node(meta_root, type="root")

    # Get all devices
    devices = sorted(set(t["device"] for t in threat_index.values()))

    # Build subtrees per device
    for dev in devices:
        dev_root = f"Compromise {dev}"
        G.add_node(dev_root, type="device")
        G.add_edge(meta_root, dev_root)

        # Attach threats for this device
        for tid, t in threat_index.items():
            if t["device"] == dev:
                score = calculate_dread_score(t["dread"])
                sev = determine_severity(score)
                label = f"{tid}: {t['description']}\n \n Impact~{sev} | Likelihood~{t['prob']}"
                G.add_node(label, type="threat")
                G.add_edge(dev_root, label)

    # Assign subset attribute for multipartite layout
    for n in G.nodes():
        if n == meta_root or "Smart Home" in n:
            G.nodes[n]['subset'] = 0
        elif "Compromise" in n:
            G.nodes[n]['subset'] = 1
        else:
            G.nodes[n]['subset'] = 2

    # Use Graphviz hierarchical layout for better grouping
    try:
        pos = nx.nx_agraph.graphviz_layout(G, prog="dot")
    except ImportError:
        pos = nx.spring_layout(G, seed=42)  # fallback

    # Colors by type
    colors = []
    node_sizes = []
    for n, d in G.nodes(data=True):
        if d["type"] == "root":
            colors.append("#B7CFDC")      # blue
            node_sizes.append(3500)
        elif d["type"] == "device":
            colors.append("#c7e9c0")      # green
            node_sizes.append(2500)
        else:
            colors.append("#fdd0a2")      # orange
            node_sizes.append(1800)

    # Wrap threat labels for readability
    def wrap_label(label, width=38):
        return '\n'.join(textwrap.wrap(label, width=width))

    labels = {}
    for n, d in G.nodes(data=True):
        if d["type"] == "threat":
            labels[n] = wrap_label(n, width=38)
        else:
            labels[n] = n

    plt.figure(figsize=(18, 12))
    nx.draw_networkx_nodes(G, pos, node_color=colors, node_size=node_sizes, alpha=0.95)
    nx.draw_networkx_edges(G, pos, arrows=True, arrowstyle='-|>', arrowsize=18, width=1.8, connectionstyle='arc3,rad=0.15', edge_color="#0EB0D8")
    nx.draw_networkx_labels(G, pos, labels=labels, font_size=9, font_weight="bold")

    # Add legend
    import matplotlib.patches as mpatches
    legend_handles = [
        mpatches.Patch(color="#B7CFDC", label="Root (System)"),
        mpatches.Patch(color="#c7e9c0", label="Device"),
        mpatches.Patch(color="#fdd0a2", label="Threat"),
    ]
    plt.legend(handles=legend_handles, loc="upper left", fontsize=11, frameon=True)

    plt.title("IoT Home System Attack Tree", fontsize=18, fontweight="bold", pad=20)
    plt.axis("off")
    plt.tight_layout()
    plt.savefig(out_path, bbox_inches="tight", dpi=150)
    plt.close()
    print(f"Attack tree saved to {out_path}")

if __name__ == "__main__":
    visualize_attack_tree("HomeSystem_Threats.json", "HomeSystem_attack_tree.png")
