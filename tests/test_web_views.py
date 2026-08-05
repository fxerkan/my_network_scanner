"""Wiring checks for the layout switch (card/table/map/graph/topology/home).

Cheap guards against the two ways these views break silently: a button whose
container was never added, and a tr() key that exists in one language only.
"""

import json
import re
from pathlib import Path

WEB = Path(__file__).resolve().parents[1] / "mynes" / "web"
INDEX = (WEB / "templates" / "index.html").read_text(encoding="utf-8")
VIEWS_JS = (WEB / "static" / "js" / "views.js").read_text(encoding="utf-8")
MAIN_JS = (WEB / "static" / "js" / "main.js").read_text(encoding="utf-8")


def test_every_view_button_has_a_container_and_a_dispatch():
    views = set(re.findall(r"switchView\('(\w+)'\)", INDEX))
    assert views == {"card", "table", "graph", "topology", "home"}, views

    containers = {
        "card": "devicesContainer",
        "table": "tableContainer",
        "graph": "graphContainer",
        "topology": "topologyContainer",
        "home": "homeContainer",
    }
    for view in views:
        assert f'id="{containers[view]}"' in INDEX, f"{view} has no container"
        assert containers[view] in MAIN_JS, f"{view} is not toggled by switchView"


def test_views_assets_are_linked():
    assert "/static/js/views.js" in INDEX
    assert "/static/css/views.css" in INDEX
    for symbol in ("i-graph", "i-topology", "i-home"):
        assert f'href="#{symbol}"' in INDEX
        assert f'id="{symbol}"' in (WEB / "templates" / "_icons.html").read_text(encoding="utf-8")


def test_view_translation_keys_exist_in_both_languages():
    # Literal calls only - tr('group_' + key, ...) is a prefix, covered below.
    keys = set(re.findall(r"tr\('([a-z0-9_]+)',", VIEWS_JS))
    keys |= {"group_" + g for g in re.findall(r"key: '(\w+)',", VIEWS_JS)}
    assert keys, "no tr() keys found - did the helper get renamed?"
    for lang in ("en", "tr"):
        table = json.loads((WEB / "locales" / lang / "translations.json").read_text(encoding="utf-8"))
        missing = sorted(keys - table.keys())
        assert not missing, f"{lang} is missing {missing}"


def demo():
    test_every_view_button_has_a_container_and_a_dispatch()
    test_views_assets_are_linked()
    test_view_translation_keys_exist_in_both_languages()
    print("views wiring ok")


if __name__ == "__main__":
    demo()


def test_graph_and_tooltip_wiring():
    """Static guards for the graph's zoom/hover work — no browser needed."""
    # The graph reuses the topology's viewBox zoom/pan instead of a second one.
    assert "attachZoomPan(stage, svg, box)" in VIEWS_JS
    assert VIEWS_JS.count("function attachZoomPan") == 1
    # Zoom buttons must not be swallowed by the pan handler, and neither must
    # graph nodes - a node that starts a drag never fires its click.
    assert ".topo-node, .graph-node, .topo-zoom" in VIEWS_JS
    # Hover card, including the Docker facts the plain <title> could not show.
    for key in ("docker_stack", "docker_network", "docker_image", "docker_host"):
        assert key in VIEWS_JS, key
    # Containers hang off their host, so no subnet hub is minted for them.
    assert "dockerHostIp" in VIEWS_JS


def test_tooltip_and_docker_keys_exist_in_both_languages():
    keys = ("docker_stack", "docker_image", "docker_host", "combined_rules",
            "shared_segment", "all_stacks", "no_stack")
    for lang in ("en", "tr"):
        table = json.loads((WEB / "locales" / lang / "translations.json").read_text(encoding="utf-8"))
        for key in keys:
            assert key in table, f"{key} missing from {lang}"
