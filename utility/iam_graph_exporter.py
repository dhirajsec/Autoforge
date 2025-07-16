import matplotlib.pyplot as plt
import networkx as nx
from datetime import datetime
import os

def render_iam_graph(results):
    G = nx.DiGraph()

    for item in results:
        path = item.get("path")
        if path:
            for edge in path:
                source = edge.get("source", "unknown-source")
                target = edge.get("target", "unknown-target")
                action = edge.get("action", "unknown-action")
                severity = edge.get("severity", "info")

                color = {
                    "high": "red",
                    "medium": "orange",
                    "low": "green",
                    "info": "gray"
                }.get(severity, "gray")

                G.add_edge(source, target, label=action, color=color)
        else:
            source = item.get("source", "unknown-principal")
            target = item.get("target", "unknown-resource")
            action = item.get("action", "unknown-action")
            severity = item.get("severity", "info")

            color = {
                "high": "red",
                "medium": "orange",
                "low": "green",
                "info": "gray"
            }.get(severity, "gray")

            G.add_edge(source, target, label=action, color=color)

    # 🌐 Improve layout spacing
    pos = nx.spring_layout(G, k=1.0, seed=42)

    edge_colors = [G[u][v]["color"] for u, v in G.edges()]
    edge_labels = nx.get_edge_attributes(G, "label")

    # 🖼️ Enhanced edge drawing with arrows
    nx.draw(
        G, pos,
        with_labels=True,
        edge_color=edge_colors,
        node_color="skyblue",
        node_size=2500,
        arrows=True,
        arrowsize=25,
        connectionstyle='arc3,rad=0.2',
        font_size=11
    )

    # 📝 Draw edge labels
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=9)

    # 📂 Save graph image with better resolution
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
    os.makedirs("static/reports", exist_ok=True)
    filename = f"static/reports/iam_graph_{timestamp}.png"

    plt.title("IAM Access Graph (Multi-Hop)")
    plt.tight_layout()
    plt.savefig(filename, dpi=150)
    plt.close()

    summary = {
        "total_nodes": len(G.nodes()),
        "total_edges": len(G.edges()),
        "high_risk_edges": sum(
            1 for u, v in G.edges() if G[u][v]["color"] == "red"
        )
    }

    print(f"✅ IAM graph saved as {filename}")
    return summary, filename
