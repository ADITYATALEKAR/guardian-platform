from __future__ import annotations

import re
import threading
import time
from typing import Dict, Tuple


class MetricsRegistry:
    """
    Thread-safe Prometheus-compatible metrics registry.

    Supports:
    - Counters
    - Gauges
    - Histograms
    - Label dimensions
    """

    def __init__(self):
        self._lock = threading.Lock()

        # (name, frozenset(labels)) -> value
        self._counters: Dict[Tuple[str, Tuple[Tuple[str, str], ...]], float] = {}
        self._gauges: Dict[Tuple[str, Tuple[Tuple[str, str], ...]], float] = {}
        self._histograms: Dict[str, Dict[str, float]] = {}

    # ============================================================
    # Label Normalization
    # ============================================================

    def _label_key(self, labels: Dict[str, str] | None) -> Tuple[Tuple[str, str], ...]:
        if not labels:
            return tuple()
        return tuple(
            sorted(
                (
                    self._sanitize_label_name(str(key)),
                    self._sanitize_label_value(str(value)),
                )
                for key, value in labels.items()
            )
        )

    @staticmethod
    def _sanitize_label_name(label: str) -> str:
        sanitized = re.sub(r"[^a-zA-Z0-9_]", "_", label.strip())
        return sanitized or "label"

    @staticmethod
    def _sanitize_label_value(value: str) -> str:
        return value.replace("\\", "\\\\").replace("\n", " ").replace('"', '\\"').strip()

    # ============================================================
    # Counters
    # ============================================================

    def inc(self, name: str, value: float = 1.0, labels: Dict[str, str] | None = None):
        key = (name, self._label_key(labels))
        with self._lock:
            self._counters[key] = self._counters.get(key, 0.0) + value

    # ============================================================
    # Gauges
    # ============================================================

    def set_gauge(self, name: str, value: float, labels: Dict[str, str] | None = None):
        key = (name, self._label_key(labels))
        with self._lock:
            self._gauges[key] = value

    # ============================================================
    # Histogram (cycle latency)
    # ============================================================

    def observe_histogram(
        self,
        name: str,
        value: float,
        buckets: Tuple[float, ...] = (0.5, 1, 2, 5, 10, 30, 60, 120),
    ):
        """
        Records histogram observation.
        Buckets in seconds.
        """
        with self._lock:
            if name not in self._histograms:
                self._histograms[name] = {
                    "count": 0,
                    "sum": 0.0,
                }
                for b in buckets:
                    self._histograms[name][f"le_{b}"] = 0

            hist = self._histograms[name]
            hist["count"] += 1
            hist["sum"] += value

            for b in buckets:
                if value <= b:
                    hist[f"le_{b}"] += 1

    # ============================================================
    # Export
    # ============================================================

    def render_prometheus(self) -> str:
        lines = []

        with self._lock:

            # Counters
            for (name, labels), value in self._counters.items():
                label_str = self._format_labels(labels)
                lines.append(f"# TYPE {name} counter")
                lines.append(f"{name}{label_str} {value}")

            # Gauges
            for (name, labels), value in self._gauges.items():
                label_str = self._format_labels(labels)
                lines.append(f"# TYPE {name} gauge")
                lines.append(f"{name}{label_str} {value}")

            # Histograms
            for name, hist in self._histograms.items():
                lines.append(f"# TYPE {name} histogram")

                for key, val in hist.items():
                    if key.startswith("le_"):
                        bucket = key.replace("le_", "")
                        lines.append(
                            f"{name}_bucket{{le=\"{bucket}\"}} {val}"
                        )

                lines.append(f"{name}_count {hist['count']}")
                lines.append(f"{name}_sum {hist['sum']}")

        return "\n".join(lines) + "\n"

    def _format_labels(self, labels: Tuple[Tuple[str, str], ...]) -> str:
        if not labels:
            return ""
        pairs = ",".join(f'{k}="{v}"' for k, v in labels)
        return "{" + pairs + "}"
