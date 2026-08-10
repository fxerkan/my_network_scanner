"""The CVE reference-store and curated-CVE self-checks are the cheapest layer.

Both modules carry a runnable demo() with asserts; run them here so a broken
SQLite store or a broken enrichment path fails in CI, not in the browser.
"""

from mynes.security import cve, cve_store


def test_cve_store_demo():
    """upsert_records / get_record / search / stats on a throwaway DB."""
    assert cve_store.demo() is True


def test_cve_demo():
    """Curated matching + official-DB enrichment overlay (hermetic)."""
    assert cve.demo() is True
