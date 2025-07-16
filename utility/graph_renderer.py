import matplotlib
matplotlib.use("Agg")

import networkx as nx
import matplotlib.pyplot as plt
from datetime import datetime
import os

def detect_node_type(name):
    if "Lambda" in name:
        return "Lambda"
    elif "Role" in name or "admin" in name:
        return "IAM_Role"
    elif "Bucket" in name or "S3" in name:
        return "S3_Bucket"
    return "Unknown"

def render_annotated_graph(results, output_dir="static/reports", show_audit=True):
    G = nx.DiGraph()

    severity_colors = {
        "high": "red",
        "medium": "orange",
        "info": "gray",
        "low": "lightgreen"
    }

    node_type_palette = {
        "Lambda": "plum",
        "IAM_Role": "mediumseagreen",
        "S3_Bucket": "skyblue",
        "Unknown": "lightgray"
    }

    edge_labels = {}
    node_colors = {}

    for result in results:
        for edge in result.get("path", []):
            source = edge.get("source")
            target = edge.get("target")
            severity = edge.get("severity", "low")
            message = edge.get("message", "")
            action = edge.get("action", "")

            if severity == "info" and not show_audit:
                continue

            color = severity_colors.get(severity, "lightblue")
            G.add_edge(source, target, color=color)

            edge_labels[(source, target)] = f"{action}\n{message}" if message else action

            node_colors[source] = node_type_palette.get(detect_node_type(source), "lightgray")
            node_colors[target] = node_type_palette.get(detect_node_type(target), "lightgray")

    try:
        pos = nx.kamada_kawai_layout(G)
    except Exception:
        pos = nx.spring_layout(G, seed=42)

    edge_colors = [G[u][v]["color"] for u, v in G.edges()]
    node_color_values = [node_colors.get(n, "lightgray") for n in G.nodes()]

    plt.figure(figsize=(12, 8))
    nx.draw(
        G, pos,
        with_labels=True,
        edge_color=edge_colors,
        node_color=node_color_values,
        node_size=1800,
        font_size=10
    )
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=8)
    plt.title("🔐 IAM Trust Graph (Clustered & Annotated)")
    plt.axis("off")

    for sev, color in severity_colors.items():
        plt.plot([], [], color=color, label=sev.capitalize())

    plt.legend(loc="lower left")

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
    image_path = os.path.join(output_dir, f"iam_graph_{timestamp}.png")
    plt.tight_layout()
    plt.savefig(image_path)
    plt.close()

    print(f"✅ IAM graph saved as {image_path}")
    return {"nodes": len(G.nodes()), "edges": len(G.edges())}, image_path