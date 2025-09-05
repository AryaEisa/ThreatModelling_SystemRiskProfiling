import json
import networkx as nx
import matplotlib.pyplot as plt

def build_threat_index(threats_path):
    with open(threats_path, "r", encoding="utf-8") as f:
        threats = json.load(f)
    return {t["id"]: t for t in threats if "id" in t}

def add_tree_nodes(G, node, threat_index, parent=None, level=1, node_levels=None):
    if node_levels is None:
        node_levels = {}
    if "ref" in node:
        tid = node["ref"]
        threat = threat_index.get(tid, {})
        label = f"{tid}\nP={threat.get('prob','')}\n{threat.get('description','')}"
        G.add_node(tid, label=label, color="#f9f9c5", shape="box", level=level)
        node_levels[tid] = level
        if parent:
            G.add_edge(parent, tid)
    else:
        logic = node.get("logic", "OR")
        nid = str(id(node))
        G.add_node(nid, label=logic, color="#e0e0e0", shape="ellipse", level=level)
        node_levels[nid] = level
        if parent:
            G.add_edge(parent, nid)
        for child in node.get("children", []):
            add_tree_nodes(G, child, threat_index, nid, level+1, node_levels)
    return node_levels

def visualize_attack_tree(tree_path, threats_path):
    with open(tree_path, "r", encoding="utf-8") as f:
        tree = json.load(f)
    threat_index = build_threat_index(threats_path)
    G = nx.DiGraph()
    root_label = tree.get("root", "Root")
    root_id = "root"
    G.add_node(root_id, label=root_label, color="#b3cde0", shape="doublecircle", level=0)
    node_levels = {}
    for child in tree.get("children", []):
        node_levels.update(add_tree_nodes(G, child, threat_index, root_id, 1, node_levels))
    node_levels[root_id] = 0

    # Hierarchical layout using multipartite_layout
    pos = nx.multipartite_layout(G, subset_key="level", align="vertical")

    # Draw nodes with color and shape
    node_colors = [G.nodes[n].get("color", "#cccccc") for n in G.nodes()]
    nx.draw_networkx_edges(G, pos, arrows=True, arrowstyle='-|>', edge_color="#555555")
    nx.draw_networkx_labels(G, pos, labels=nx.get_node_attributes(G, 'label'), font_size=9)
    nx.draw_networkx_nodes(
        G, pos,
        node_color=node_colors,
        node_size=2200,
        edgecolors="#333333",
        linewidths=1.5
    )

    plt.title("Attack Tree", fontsize=14, fontweight="bold")
    plt.axis("off")
    plt.tight_layout()
    plt.savefig("attack_tree.png")
    plt.show()

if __name__ == "__main__":
    visualize_attack_tree("attack_tree.json", "smarttv_threats.json")