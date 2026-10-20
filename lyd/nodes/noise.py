"""Noise tuning node: flags use cases whose alerts look like repeated false positives.

Evidence used (from alert statistics): weekly volume, share of alerts closed
as false positive by analysts, and the dominant cluster of alerts. It never
decides on its own: it raises `noisy_rule` with the evidence, the builder
proposes a narrow exclusion, validation and an engineer decide.
"""
from __future__ import annotations

from .base import Context, Emit, Node


class NoiseTuningNode(Node):
    name = "noise_tuning"
    subscribes = ("tick",)

    def handle(self, event, ctx: Context) -> Emit:
        p = ctx.profile["noise"]
        out: Emit = []
        for s in ctx.alert_stats:
            cluster = s.get("top_cluster") or {}
            if (s["alerts_7d"] >= p["min_alerts_7d"] and s["fp_closed_ratio"] >= p["min_fp_ratio"]
                    and cluster.get("share", 0) >= p["min_cluster_share"]):
                out.append(("noisy_rule", {"use_case": s["use_case"], "alerts_7d": s["alerts_7d"],
                                           "fp_closed_ratio": s["fp_closed_ratio"], "cluster": cluster}))
        return out
