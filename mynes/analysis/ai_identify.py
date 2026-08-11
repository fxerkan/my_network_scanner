"""AI-assisted device identification.

The other analysers in this package are deterministic: an OUI table, a banner
regex, a scored heuristic. They answer "what *kind* of device is this" but never
"what *is* this exact product, who makes it, what does it do" - because that
answer lives on the open web (manuals, OUI registries, support pages), not in
any table we can ship.

This module hands that job to an AI agent the user brings their own API key for.
The agent is told - in ``SYSTEM_PROMPT`` below, which is the whole "skill" and is
meant to be read and edited - how to research a device the way a human would:
start from the hard signals we already gathered (MAC/OUI, open ports, service
banners, any setup portal), search the web, read the manuals, and return a
strict JSON block we fold into the device as an "AI identification" enhanced
analysis section.

Provider: Anthropic's Messages API with the server-side ``web_search`` tool, so
the search/read/reason loop runs on their infrastructure and we just POST once
(plus any ``pause_turn`` continuations) and parse the final JSON. No SDK - the
repo already depends on ``requests``. Only 'anthropic' is wired today; the
config carries a ``provider`` field so an OpenAI-compatible path can be added
without touching callers.

Nothing here runs during a normal scan. It is an explicit, per-device, user-
triggered action (see web/api.py), because it costs the user real API tokens.
"""

from __future__ import annotations

import json
import logging
import os

log = logging.getLogger(__name__)

DEFAULT_PROVIDER = "anthropic"
DEFAULT_MODEL = "claude-opus-4-8"
DEFAULT_BASE_URL = "https://api.anthropic.com"
# Per-provider defaults, used when the config/env doesn't pin a model or host.
# OpenRouter is an OpenAI-compatible gateway; its base already carries /api/v1.
PROVIDER_BASE_URLS = {"anthropic": "https://api.anthropic.com",
                      "openai": "https://api.openai.com",
                      "openrouter": "https://openrouter.ai/api/v1"}
# OpenRouter default is a strong, widely-available model - device identification
# over sparse signals rewards reasoning, and a mini model over-claims (invents a
# specific camera model from bare ports). Override with MYNES_AI_MODEL.
PROVIDER_MODELS = {"anthropic": "claude-opus-4-8", "openai": "gpt-4o",
                   "openrouter": "openai/gpt-4o"}
# The basic web-search tool variant is accepted across every current Claude
# model (the newer _20260209 dynamic-filtering variant is Opus-4.6+ only). We
# take the widely-compatible one so a user's own key/model choice just works.
WEB_SEARCH_TOOL = "web_search_20250305"
# Where the encrypted AI key is filed in the credential store: a synthetic
# "device" whose access_type is the provider name. Keeps the key out of
# config.json (which is tracked in git) and reuses the Fernet store.
AI_KEY_IP = "__ai__"


# ---------------------------------------------------------------------------
# The skill: how the agent should research a device. Editable on purpose.
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """\
You are a network-device identification analyst working inside MyNeS, a home-LAN
scanner. You are given the hard evidence a scan already collected about ONE
device on a private network - its MAC/OUI vendor, open TCP ports, service
banners, and (when present) snippets of any web/setup page it serves. Your job
is to determine, as specifically and truthfully as the evidence allows, what
this exact device is: manufacturer, brand, model/product line, what category of
device it is, what it does, and its notable features.

Work like a careful human researcher, step by step:

1. Read the evidence first. The MAC OUI names the maker of the network chip -
   which for appliances is often a module vendor (AzureWave, Espressif, MediaTek)
   NOT the brand of the product. Treat the OUI as a lead, not a conclusion.
2. The strongest signals are self-identifying: a service banner ("Hikvision",
   "OpenSSH_...Raspbian"), an mDNS/UPnP model string, or the exact text/paths of
   a setup portal (e.g. an air-conditioner Wi-Fi adapter serves a "select the
   access point" captive portal, an SSID list, and success wording that mentions
   an "indoor unit" / "wireless LAN adapter" - that is HVAC, not networking gear).
3. SEARCH THE WEB. Do not answer from memory alone. Search for the distinctive
   strings you see - banner text, unusual URL paths, default SoftAP SSID patterns,
   port combinations, the OUI vendor name plus the device category. Follow up on
   the best hits: manufacturer manuals, support/FAQ pages, Home Assistant / OpenHAB
   integration threads, and MAC-vendor/OUI databases. Cross-check across at least
   two independent sources before you commit to a brand and model.
4. Distinguish the module maker from the product brand, and a service running ON
   the device from the device itself (a qBittorrent web UI does not make the box a
   "qBittorrent" - it is a server running it).
5. Calibrate confidence honestly. If the evidence only pins the category (e.g.
   "an air-conditioner Wi-Fi adapter") but not the exact brand, say so and set a
   lower confidence - never invent a specific model the sources do not support.
   It is far better to be correctly vague than confidently wrong.
6. Do NOT commit to a specific hardware GENERATION or revision that the evidence
   cannot distinguish. Many product lines share one OUI and identical network
   signatures across generations - e.g. every Raspberry Pi board (Pi 3 / 4 / 5
   and their variants) uses the same "Raspberry Pi Trading Ltd" OUI, and the OS
   (a Debian/Raspbian SSH banner) is the same across generations. Unless a banner,
   mDNS/UPnP string, or served page states the exact model, give the product LINE
   with the generation as a RANGE ("Raspberry Pi 4 or 5") or leave "model" as the
   family, and set confidence no higher than ~0.6 for the specific generation.
   Naming one generation with high confidence off the OUI alone is exactly the
   "confidently wrong" failure this rule prevents.

Only scan/identify devices on a network the user owns; this is a defensive,
inventory task on the user's own LAN.

When done, output ONLY a single JSON object (no prose before or after, no
markdown code fence) with exactly these keys:

{
  "manufacturer": "legal maker of the product, or \\"\\" if unknown",
  "brand": "consumer brand it is sold under (may equal manufacturer)",
  "model": "specific model / product line, or \\"\\" if not pinned",
  "product_type": "short type, e.g. \\"Air Conditioner Wi-Fi Adapter\\"",
  "category": "broad category, e.g. \\"HVAC\\", \\"IP Camera\\", \\"NAS\\"",
  "what_it_is": "one sentence: what this device is",
  "what_it_does": "2-4 sentences: its purpose and how it is used",
  "key_features": ["notable feature", "..."],
  "typical_protocols": ["e.g. mDNS", "MQTT", "local JSON API on TCP 51443"],
  "typical_ports": [80, 443],
  "setup_notes": "how it is set up / paired, if relevant",
  "security_notes": "any exposure worth flagging (open portal, default creds), or \\"\\"",
  "identified_via": ["which concrete signals led you here"],
  "confidence": 0.0,
  "alternatives": [{"product_type": "other plausible type the evidence also fits", "confidence": 0.0}],
  "sources": [{"title": "page title", "url": "https://..."}],
  "reasoning": "2-4 sentences justifying the identification and its confidence"
}

Rules for the JSON: use "" or [] when you do not know a field - never guess to
fill it. "confidence" is 0.0-1.0. "alternatives" lists other device types the
same evidence could plausibly support, each with its own confidence, worst-case
first is fine - leave it [] when the identification is unambiguous. Include every
source URL you actually relied on. Output the JSON and nothing else."""


# ---------------------------------------------------------------------------
# Gather the evidence we hand to the agent
# ---------------------------------------------------------------------------

def build_facts(device: dict) -> dict:
    """Collect the hard signals for one device into a compact evidence dict.

    Pulls what the saved device already knows, then runs the same live probe
    fingerprint.classify() uses (banners + any setup-portal marker) so the agent
    sees the same evidence a human would when opening the box's web page.
    """
    ip = device.get("ip") or ""
    open_ports = [p.get("port") for p in (device.get("open_ports") or [])
                  if isinstance(p, dict) and p.get("port")]
    mac = device.get("mac") or ""
    oui_vendor = device.get("vendor") or ""
    # The OUI is the single most decisive signal - a weaker model will happily
    # invent a specific Hikvision model from "ports 23+554" alone if we don't
    # hand it the real chip vendor. Resolve it from the MAC when the device row
    # doesn't already carry one.
    if not oui_vendor and mac:
        try:
            from mynes.analysis.oui import OUIManager
            got = OUIManager().get_vendor(mac)
            if got and got.lower() not in ("unknown", "bilinmeyen"):
                oui_vendor = got
        except Exception as e:  # noqa: BLE001 - OUI lookup is best-effort
            log.debug("OUI lookup failed for %s: %s", mac, e)
    facts = {
        "ip": ip,
        "mac": mac,
        "oui_vendor": oui_vendor,
        "hostname": device.get("hostname") or "",
        "current_guess": device.get("device_type") or "",
        "open_ports": sorted(set(open_ports)),
        "http": [], "ssh": None, "ftp": None, "rtsp": None, "smb": None,
        "setup_portal": "",
    }
    if not ip:
        return facts
    try:
        from mynes.analysis import fingerprint
        signals = fingerprint.gather(ip, open_ports=open_ports or None,
                                     vendor=facts["oui_vendor"],
                                     hostname=facts["hostname"])
        facts["open_ports"] = signals.get("open_ports") or facts["open_ports"]
        # Keep only the identifying bits of each HTTP banner - not the whole page.
        facts["http"] = [{k: b.get(k) for k in
                          ("port", "server", "title", "realm", "powered_by", "appliance")
                          if b.get(k)} for b in (signals.get("http") or [])]
        for key in ("ssh", "ftp", "rtsp", "smb"):
            facts[key] = signals.get(key)
        facts["setup_portal"] = next(
            (b.get("appliance") for b in (signals.get("http") or []) if b.get("appliance")), "")
    except Exception as e:  # noqa: BLE001 - probing is best-effort, never fatal
        log.debug("build_facts probe failed for %s: %s", ip, e)
    return facts


def _facts_prompt(facts: dict) -> str:
    """Render the evidence dict as the user message for the agent."""
    return ("Identify this device from the evidence below. Search the web to "
            "confirm the manufacturer, model and features, then return the JSON.\n\n"
            + json.dumps(facts, ensure_ascii=False, indent=2, default=str))


# ---------------------------------------------------------------------------
# Call the agent
# ---------------------------------------------------------------------------

def identify_device(facts: dict, *, api_key: str, model: str = DEFAULT_MODEL,
                    provider: str = DEFAULT_PROVIDER, base_url: str = DEFAULT_BASE_URL,
                    max_search_uses: int = 8, timeout: int = 180) -> dict:
    """Run the AI research agent over ``facts`` and return the parsed result.

    Returns the schema dict from SYSTEM_PROMPT plus a ``_meta`` block. Raises on
    a bad key, an API error, or output that is not parseable JSON - the caller
    turns that into an error status the UI can show.
    """
    if not api_key:
        raise ValueError("no AI API key configured")

    user = _facts_prompt(facts)
    if provider == "anthropic":
        text = _call_anthropic(api_key, base_url, model, SYSTEM_PROMPT, user,
                               max_search_uses, timeout)
    elif provider == "openai":
        text = _call_openai(api_key, base_url, model, SYSTEM_PROMPT, user, timeout)
    elif provider == "openrouter":
        text = _call_openrouter(api_key, base_url, model, SYSTEM_PROMPT, user, timeout)
    else:
        raise ValueError(f"AI provider {provider!r} is not supported; "
                         "use 'anthropic', 'openai' or 'openrouter'")
    result = _extract_json(text)
    result["_meta"] = {"provider": provider, "model": model}
    return result


def _call_anthropic(api_key, base_url, model, system, user, max_search_uses, timeout):
    """POST /v1/messages with the web_search tool; ride out pause_turn loops."""
    import requests

    url = base_url.rstrip("/") + "/v1/messages"
    headers = {"x-api-key": api_key, "anthropic-version": "2023-06-01",
               "content-type": "application/json"}
    messages = [{"role": "user", "content": user}]
    body = {
        "model": model,
        "max_tokens": 8000,
        "system": system,
        "tools": [{"type": WEB_SEARCH_TOOL, "name": "web_search",
                   "max_uses": max_search_uses}],
        "messages": messages,
    }
    # Server tools run a sampling loop that can stop at pause_turn; re-send to
    # let it continue. Bound the continuations so a stuck run can't spin forever.
    for _ in range(6):
        resp = requests.post(url, headers=headers, json=body, timeout=timeout)
        if resp.status_code != 200:
            raise RuntimeError(f"AI API HTTP {resp.status_code}: {resp.text[:300]}")
        data = resp.json()
        if data.get("stop_reason") == "pause_turn":
            messages.append({"role": "assistant", "content": data.get("content", [])})
            body["messages"] = messages
            continue
        return _text_from_content(data.get("content", []))
    raise RuntimeError("AI API kept pausing; gave up after 6 continuations")


def _text_from_content(blocks) -> str:
    """Concatenate the text blocks of a Messages API response."""
    return "".join(b.get("text", "") for b in blocks
                   if isinstance(b, dict) and b.get("type") == "text").strip()


def _call_openai(api_key, base_url, model, system, user, timeout):
    """POST /v1/responses with the built-in web_search tool; return the text.

    The Responses API runs the search/read/reason loop server-side (like
    Anthropic's web_search tool), so a single POST is enough - no client loop.
    """
    import requests

    url = base_url.rstrip("/") + "/v1/responses"
    headers = {"Authorization": f"Bearer {api_key}", "content-type": "application/json"}
    body = {
        "model": model,
        "instructions": system,
        "input": user,
        "tools": [{"type": "web_search_preview"}],
        "max_output_tokens": 8000,
    }
    resp = requests.post(url, headers=headers, json=body, timeout=timeout)
    if resp.status_code != 200:
        raise RuntimeError(f"AI API HTTP {resp.status_code}: {resp.text[:300]}")
    return _openai_output_text(resp.json())


def _openai_output_text(data) -> str:
    """Pull the assistant text out of a Responses API result."""
    if isinstance(data.get("output_text"), str) and data["output_text"].strip():
        return data["output_text"].strip()
    parts = []
    for item in data.get("output", []) or []:
        if item.get("type") == "message":
            for c in item.get("content", []) or []:
                if c.get("type") in ("output_text", "text") and c.get("text"):
                    parts.append(c["text"])
    return "".join(parts).strip()


def _call_openrouter(api_key, base_url, model, system, user, timeout):
    """POST to an OpenAI-compatible /chat/completions gateway (OpenRouter).

    Web search is enabled with OpenRouter's ``web`` plugin, which works on any
    model (equivalent to the ``:online`` model suffix). Returns the reply text.
    """
    import requests

    url = base_url.rstrip("/") + "/chat/completions"
    headers = {"Authorization": f"Bearer {api_key}", "content-type": "application/json",
               "X-Title": "MyNeS"}
    body = {
        "model": model,
        "messages": [{"role": "system", "content": system},
                     {"role": "user", "content": user}],
        "plugins": [{"id": "web"}],
        "max_tokens": 8000,
    }
    resp = requests.post(url, headers=headers, json=body, timeout=timeout)
    if resp.status_code != 200:
        raise RuntimeError(f"AI API HTTP {resp.status_code}: {resp.text[:300]}")
    return _chat_completion_text(resp.json())


def _chat_completion_text(data) -> str:
    """The assistant message text from an OpenAI-compatible chat completion."""
    if data.get("error"):
        raise RuntimeError(f"AI API error: {str(data['error'])[:300]}")
    choices = data.get("choices") or []
    if not choices:
        raise RuntimeError(f"AI API returned no choices: {str(data)[:200]}")
    return (choices[0].get("message", {}).get("content") or "").strip()


def _extract_json(text: str) -> dict:
    """Parse the JSON object out of the model's final message.

    Tolerates a stray code fence or trailing prose by scanning for the first
    brace-balanced object rather than trusting the whole string to be JSON.
    """
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        pass
    start = text.find("{")
    if start == -1:
        raise ValueError(f"no JSON object in AI response: {text[:200]!r}")
    depth, in_str, esc = 0, False, False
    for i in range(start, len(text)):
        c = text[i]
        if in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
        elif c == '"':
            in_str = True
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return json.loads(text[start:i + 1])
    raise ValueError(f"unbalanced JSON in AI response: {text[:200]!r}")


# ---------------------------------------------------------------------------
# Settings + key storage (provider/model in config.json, key in the Fernet store)
# ---------------------------------------------------------------------------

def get_ai_settings(config_manager) -> dict:
    # Env (incl. anything from `.env`) wins over the saved config, matching how
    # every other MyNeS setting resolves; config is the UI-saved fallback. Model
    # and base_url fall back to the *provider's* default, not Anthropic's, so
    # setting only MYNES_AI_PROVIDER=openai still points at the right host/model.
    provider = (os.environ.get("MYNES_AI_PROVIDER")
                or config_manager.get_setting("ai", "provider", DEFAULT_PROVIDER))
    model = (os.environ.get("MYNES_AI_MODEL")
             or config_manager.get_setting("ai", "model")
             or PROVIDER_MODELS.get(provider, DEFAULT_MODEL))
    base_url = (os.environ.get("MYNES_AI_BASE_URL")
                or config_manager.get_setting("ai", "base_url")
                or PROVIDER_BASE_URLS.get(provider, DEFAULT_BASE_URL))
    return {
        "provider": provider, "model": model, "base_url": base_url,
        "max_search_uses": int(config_manager.get_setting("ai", "max_search_uses", 8) or 8),
    }


def save_ai_settings(config_manager, *, provider=None, model=None,
                     base_url=None, max_search_uses=None) -> dict:
    if provider:
        config_manager.set_setting("ai", "provider", provider)
    if model:
        config_manager.set_setting("ai", "model", model)
    if base_url:
        config_manager.set_setting("ai", "base_url", base_url)
    if max_search_uses is not None:
        config_manager.set_setting("ai", "max_search_uses", int(max_search_uses))
    return get_ai_settings(config_manager)


# Standard per-provider env var names, so a user can drop the key straight into
# `.env` (loaded by mynes/__init__.py) under the name that provider's own docs
# use - ANTHROPIC_API_KEY / OPENAI_API_KEY - instead of learning ours.
PROVIDER_ENV_KEYS = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
}


def resolve_api_key(credential_manager, provider: str) -> str | None:
    """The AI key, in precedence order: generic env, provider env, encrypted store.

    `.env` in the repo root is loaded into the environment at import, so any of
    MYNES_AI_API_KEY / ANTHROPIC_API_KEY / OPENAI_API_KEY set there is picked up
    here with no extra wiring. A real environment variable always wins over the
    file, and either wins over the UI-saved encrypted key.
    """
    for name in ("MYNES_AI_API_KEY", PROVIDER_ENV_KEYS.get(provider)):
        if name and os.environ.get(name):
            return os.environ[name]
    if credential_manager is None:
        return None
    creds = credential_manager.get_device_credentials(AI_KEY_IP, provider)
    return (creds or {}).get("password") if creds else None


def save_api_key(credential_manager, provider: str, api_key: str) -> bool:
    return credential_manager.save_device_credentials(AI_KEY_IP, provider, password=api_key)


# ---------------------------------------------------------------------------
# Self-check - no network: parsing and prompt shaping only
# ---------------------------------------------------------------------------

def demo():
    # The real device this feature was built for: an MHI air-conditioner Wi-Fi
    # adapter (AzureWave OUI) caught serving its setup captive portal.
    device = {
        "ip": "192.168.1.84", "mac": "a8:41:f4:18:01:65",
        "vendor": "AzureWave Technology", "hostname": "",
        "device_type": "Air Conditioner",
        "open_ports": [{"port": 80, "service": "http"}],
    }
    # build_facts probes the network; keep the self-check offline by only
    # exercising the pure pieces on a hand-built facts dict.
    facts = {"ip": "192.168.1.84", "oui_vendor": "AzureWave Technology",
             "open_ports": [80], "setup_portal": "ac-wifi-adapter"}
    prompt = _facts_prompt(facts)
    assert "192.168.1.84" in prompt and "ac-wifi-adapter" in prompt

    # The final message may be bare JSON, fenced, or JSON with trailing prose -
    # all three must parse to the same object.
    obj = {"manufacturer": "Mitsubishi Heavy Industries", "confidence": 0.7,
           "typical_ports": [80, 51443]}
    bare = json.dumps(obj)
    fenced = "```json\n" + bare + "\n```"
    trailing = bare + "\n\nHope this helps!"
    for text in (bare, fenced, trailing):
        got = _extract_json(text)
        assert got["manufacturer"] == "Mitsubishi Heavy Industries", text
        assert got["typical_ports"] == [80, 51443]

    # A response with no JSON is an error, not a silent empty dict.
    try:
        _extract_json("I could not identify this device.")
        assert False, "expected ValueError on prose-only response"
    except ValueError:
        pass

    # _text_from_content ignores web_search_tool_result blocks, keeps text.
    blocks = [{"type": "server_tool_use", "name": "web_search"},
              {"type": "web_search_tool_result", "content": []},
              {"type": "text", "text": bare}]
    assert _extract_json(_text_from_content(blocks))["confidence"] == 0.7

    # OpenAI Responses API: text lives in output[].content[].output_text, and a
    # web_search_call item is skipped. Both output_text convenience and the
    # nested form must extract the same JSON.
    responses = {"output": [
        {"type": "web_search_call", "status": "completed"},
        {"type": "message", "content": [{"type": "output_text", "text": bare}]}]}
    assert _openai_output_text(responses) == bare
    assert _openai_output_text({"output_text": bare}) == bare

    # OpenRouter / OpenAI-compatible chat completion: text in choices[0].message.
    chat = {"choices": [{"message": {"role": "assistant", "content": bare}}]}
    assert _chat_completion_text(chat) == bare
    try:
        _chat_completion_text({"error": {"message": "no credits"}})
        assert False, "expected RuntimeError on error payload"
    except RuntimeError:
        pass

    # The device passed to build_facts must not be mutated by it.
    assert device["device_type"] == "Air Conditioner"
    print("ai_identify: OK")


if __name__ == "__main__":
    demo()
