"""Metrics exporters (Prometheus text + InfluxDB line protocol). No network:
the push self-check hits an unroutable port and asserts it degrades."""

from mynes.integrations.metrics import demo


def test_metrics_self_check():
    demo()
