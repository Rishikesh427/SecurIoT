import os, json, hashlib, urllib.request

_CACHE = {}
SYSTEM = ("You explain home-network security events to non-experts. Use only the "
          "facts given. Do not invent CVEs or device details. The device was isolated "
          "from the network; never say it was restarted, fixed, or cleaned. If the "
          "evidence includes decoy_ports, say it touched a decoy, which no legitimate "
          "device does. Reply as JSON: "
          '{"plain_language": str (<=40 words), "recommended_next_step": str (<=25 words)}')

def template(ev, dev):
    if ev.get("kind") == "volume":
        return {"plain_language": "Traffic exceeded the device's calibrated baseline. This is advisory evidence; no automatic containment was requested.",
                "recommended_next_step": "Review recent activity and baseline quality before taking action."}
    acts = ", ".join(ev.get("actions_taken", [])) or "none (learning mode)"
    name = dev.get("label") or dev.get("name") or "A device"
    return {"plain_language": f"{name} showed {ev.get('kind')} behavior "
                              f"({ev.get('evidence')}). Actions taken: {acts}.",
            "recommended_next_step": "Review the device; it may need a password change or replacement."}

def explain(ev, dev):
    key = ev.get("id") or hashlib.md5(json.dumps(ev, sort_keys=True).encode()).hexdigest()
    if key in _CACHE:
        return _CACHE[key]
    facts = {"device_type": dev.get("type"), "risk_band": dev.get("band"),
             "confidence": dev.get("confidence"), "reasons": dev.get("reasons"),
             "event": ev.get("kind"), "evidence": ev.get("evidence"),
             "actions_taken": ev.get("actions_taken", [])}
    out = template(ev, dev)
    try:
        model = os.environ["GEMINI_MODEL"]
        url = ("https://generativelanguage.googleapis.com/v1beta/models/"
               f"{model}:generateContent?key={os.environ['GEMINI_API_KEY']}")
        body = {"systemInstruction": {"parts": [{"text": SYSTEM}]},
                "contents": [{"parts": [{"text": json.dumps(facts)}]}],
                "generationConfig": {"responseMimeType": "application/json",
                                     "temperature": 0.2}}
        req = urllib.request.Request(url, json.dumps(body).encode(),
                                     {"Content-Type": "application/json"})
        raw = json.load(urllib.request.urlopen(req, timeout=6))
        j = json.loads(raw["candidates"][0]["content"]["parts"][0]["text"])
        if isinstance(j.get("plain_language"), str) and isinstance(j.get("recommended_next_step"), str):
            out = {k: j[k] for k in ("plain_language", "recommended_next_step")}
    except Exception:
        pass   # any failure -> template
    _CACHE[key] = out
    return out