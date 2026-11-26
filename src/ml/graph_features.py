"""Vectorized graph construction and NetworkX feature extraction for User-Host interactions."""

import math
from typing import Dict, Iterable, Set, Tuple

import networkx as nx
import numpy as np
import pandas as pd


def build_user_host_graph(
    df: pd.DataFrame,
    sensitive_hosts: Iterable[str] | None = None,
    decay_half_life_hours: float = 24.0,
) -> Tuple[nx.Graph, Dict[str, str]]:
    """Build a weighted, time-decayed User-Host bipartite graph from aggregated edges."""
    graph = nx.Graph()
    node_types: Dict[str, str] = {}
    sens_set: Set[str] = {h.lower() for h in (sensitive_hosts or [])}

    if df.empty:
        return graph, node_types

    work = df[["timestamp", "user", "host"]].copy()
    work["timestamp"] = pd.to_datetime(work["timestamp"])
    max_ts = work["timestamp"].max()

    # Aggregate to unique (user, host) pairs first for O(|E|) graph construction on 1M+ logs
    agg = (
        work.groupby(["user", "host"], sort=False)
        .agg(last_ts=("timestamp", "max"), count=("timestamp", "size"))
        .reset_index()
    )

    age_hours = np.maximum(0.0, (max_ts - agg["last_ts"]).dt.total_seconds().values / 3600.0)
    decay = np.exp(-math.log(2) * age_hours / max(decay_half_life_hours, 1e-6))
    weights = agg["count"].values * decay

    for u_raw, h_raw, w, cnt in zip(agg["user"], agg["host"], weights, agg["count"]):
        user = f"user:{u_raw}"
        host_str = str(h_raw)
        host = f"host:{host_str}"

        if user not in graph:
            graph.add_node(user, node_type="user", is_sensitive=0)
            node_types[user] = "user"
        if host not in graph:
            is_sens = 1 if host_str.lower() in sens_set else 0
            graph.add_node(host, node_type="host", is_sensitive=is_sens)
            node_types[host] = "host"

        graph.add_edge(user, host, weight=float(w), count=int(cnt))

    return graph, node_types


def extract_graph_features(
    df: pd.DataFrame,
    time_window: str = "10min",
    sensitive_hosts: Iterable[str] | None = None,
) -> pd.DataFrame:
    """Compute structural and temporal graph features per (user, time_window) vectorized."""
    cols = [
        "user",
        "time_window",
        "user_degree",
        "user_pagerank",
        "user_betweenness",
        "min_dist_to_sensitive",
        "new_edge_ratio",
    ]
    if df.empty:
        return pd.DataFrame(columns=cols)

    work = df[["timestamp", "user", "host"]].copy()
    work["timestamp"] = pd.to_datetime(work["timestamp"])
    work["time_window"] = work["timestamp"].dt.floor(time_window)
    work["host_str"] = work["host"].astype(str)

    graph, _ = build_user_host_graph(work, sensitive_hosts=sensitive_hosts)
    sens_nodes = [
        n for n, attrs in graph.nodes(data=True)
        if attrs.get("node_type") == "host" and attrs.get("is_sensitive") == 1
    ]

    if graph.number_of_nodes() > 0 and graph.number_of_edges() > 0:
        pagerank = nx.pagerank(graph, weight="weight")
        betweenness = nx.betweenness_centrality(graph, normalized=True)
    else:
        pagerank = {}
        betweenness = {}

    user_nodes = [n for n in graph.nodes() if n.startswith("user:")]
    user_sens_dist: Dict[str, int] = {}
    for node in user_nodes:
        best = 99
        for s_node in sens_nodes:
            try:
                d = nx.shortest_path_length(graph, source=node, target=s_node)
                if d < best:
                    best = d
            except nx.NetworkXNoPath:
                continue
        user_sens_dist[node] = best

    # Vectorized new_edge_ratio: a host edge is "new" in the window where (user, host) first appears
    first_tw = work.groupby(["user", "host_str"], sort=False)["time_window"].transform("min")
    uh_win = work[["user", "time_window", "host_str"]].drop_duplicates()
    uh_win["is_new"] = (uh_win["time_window"] == first_tw.loc[uh_win.index]).astype(int)

    win_agg = (
        uh_win.groupby(["user", "time_window"], sort=False)
        .agg(total_hosts=("host_str", "size"), new_hosts=("is_new", "sum"))
        .reset_index()
    )
    win_agg["new_edge_ratio"] = np.round(
        win_agg["new_hosts"] / np.maximum(win_agg["total_hosts"], 1), 4
    )

    user_keys = "user:" + win_agg["user"].astype(str)
    win_agg["user_degree"] = user_keys.map(lambda k: int(graph.degree(k)) if k in graph else 0)
    win_agg["user_pagerank"] = user_keys.map(lambda k: float(pagerank.get(k, 0.0)))
    win_agg["user_betweenness"] = user_keys.map(lambda k: float(betweenness.get(k, 0.0)))
    win_agg["min_dist_to_sensitive"] = user_keys.map(lambda k: int(user_sens_dist.get(k, 99)))

    return win_agg[cols]
