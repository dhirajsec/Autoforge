def find_paths_by_severity(graph_data, severity="high"):
    """
    Returns all edges from the scanned graph that match a given severity.
    """
    results = []
    for result in graph_data:
        path = result.get("path", [])
        for edge in path:
            if edge.get("severity") == severity:
                results.append(edge)
    return results


def find_edges_between(graph_data, from_node=None, to_node=None):
    """
    Finds edges in the graph that match source/target criteria.
    """
    results = []
    for result in graph_data:
        path = result.get("path", [])
        for edge in path:
            source_match = from_node is None or edge.get("source") == from_node
            target_match = to_node is None or edge.get("target") == to_node
            if source_match and target_match:
                results.append(edge)
    return results


def find_nodes_by_type(graph_data, node_type):
    """
    Returns all nodes of a given type from the graph.
    Requires 'source_type' and 'target_type' fields on edges.
    """
    node_set = set()
    for result in graph_data:
        path = result.get("path", [])
        for edge in path:
            if edge.get("source_type") == node_type:
                node_set.add(edge.get("source"))
            if edge.get("target_type") == node_type:
                node_set.add(edge.get("target"))
    return list(node_set)


def get_edge_messages(graph_data):
    """
    Extracts annotated messages from edges for summary or audit logging.
    """
    messages = []
    for result in graph_data:
        path = result.get("path", [])
        for edge in path:
            msg = edge.get("message")
            if msg:
                messages.append({
                    "source": edge.get("source"),
                    "target": edge.get("target"),
                    "severity": edge.get("severity"),
                    "message": msg
                })
    return messages


def count_edges_by_severity(graph_data):
    """
    Returns a dictionary tallying edge counts per severity type.
    """
    count = {}
    for result in graph_data:
        path = result.get("path", [])
        for edge in path:
            severity = edge.get("severity", "low")
            count[severity] = count.get(severity, 0) + 1
    return count