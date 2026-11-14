"""Continuous cloud polling around packet replay; live capture is a later source."""
import importlib
from pathlib import Path
import time

from .cloud import CloudClient, CloudError
from .cloud_loop import CloudLoop
from .replay import load_devices, replay_capture
from .storage import Storage


def run_connected(capture, devices, state_dir, api_url, api_key, *, armed=False,
                  schema_path=None, once=False, detector_factory=None, decoy_ips=(), model_mode="required"):
    schema_path = schema_path or Path(__file__).resolve().parents[2] / "contract/schemas.json"
    # Replay completes locally even if the cloud is unreachable. A heartbeat
    # hook polls while parsing long captures; polling continues after EOF.
    def connect(agent):
        return CloudLoop(agent, CloudClient(api_url, api_key), schema_path, permit_arm=armed)

    last_poll = time.monotonic()
    context = {}
    def ready(agent):
        context["loop"] = connect(agent)
        # Establish policy before the first packet, including cloud learning mode.
        for error in context["loop"].tick(upload=False):
            print(f"Cloud: {error}; local processing continues")
    def progress(agent):
        nonlocal last_poll
        if time.monotonic() - last_poll >= 2:
            for error in context["loop"].tick():
                print(f"Cloud: {error}; pending work retained")
            last_poll = time.monotonic()

    factory = None
    if detector_factory:
        try:
            module, name = detector_factory.split(":", 1)
            factory = getattr(importlib.import_module(module), name)
        except (ValueError, ImportError, AttributeError) as error:
            raise ValueError("Cannot load detector factory; use an installed module:factory") from error
    result = replay_capture(capture, load_devices(devices), Storage(state_dir), armed=armed,
                            detector="ml", ready=ready, progress=progress, detector_factory=factory, decoy_ips=decoy_ips, model_mode=model_mode)
    agent = result.agent
    base, real_start = agent.clock(), time.monotonic()
    agent.clock = lambda: base + time.monotonic() - real_start
    loop = context["loop"]
    print("Connected runner: packet replay + mock enforcement; polling continues after EOF.")
    print("Detector:", detector_factory or getattr(agent.detector, "model_status", "C rules"))
    try:
        while True:
            errors = loop.tick()
            for error in errors:
                print(f"Cloud: {error}; pending work retained")
            if once:
                if errors:
                    raise CloudError("Cloud cycle incomplete; pending work retained for retry")
                return result
            time.sleep(2)
    except KeyboardInterrupt:
        print("Stopped; outbox and command acknowledgements retained on disk.")
    return result
