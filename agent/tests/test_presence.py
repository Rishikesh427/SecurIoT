"""Wi-Fi presence: disconnected devices upload as offline without touching saved restrictions."""
import json
from pathlib import Path
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "agent"))
from securiot_agent.demo_discovery import DemoDiscovery
from securiot_agent.live import build
from securiot_agent.simulation import DemoClock
from securiot_agent.wire import device_record

CAMERA = "02:00:00:00:00:20"
CONFIG = {"interface": "wlan-test", "cidr": "10.42.0.0/24", "protect_guests": True}


def setup(directory, clock):
    agent, collector = build(ROOT / "agent/fixtures/devices.json", Path(directory), clock=clock)
    return agent, DemoDiscovery(CONFIG, agent, collector, None, "wlan-test")


def poll(discovery, stations, taken_at=None):
    discovery.snapshots.put_nowait(([], None if stations is None else set(stations),
                                    time.monotonic() if taken_at is None else taken_at))
    return discovery.tick()


def ap_event(discovery, mac, joined):
    discovery.station_events.put((joined, mac, time.monotonic()))
    return discovery.tick()


def kinds(directory, mac=CAMERA):
    rows = [json.loads(line) for line in (Path(directory) / "outbox.jsonl").read_text().splitlines()]
    return [row["kind"] for row in rows if row["mac"] == mac]


def test_device_goes_offline_after_grace_and_returns_when_associated():
    with tempfile.TemporaryDirectory() as directory:
        clock = DemoClock(1000)
        agent, discovery = setup(directory, clock)
        camera = agent.inventory.get(CAMERA)
        camera.last_seen = 1000
        poll(discovery, {CAMERA})
        assert camera.present and device_record(camera)["status"] == "normal"

        poll(discovery, set())
        clock.advance(DemoDiscovery.OFFLINE_AFTER - 1)
        poll(discovery, set())
        assert camera.present, "a short drop must not flicker the dashboard"

        clock.advance(1)
        poll(discovery, set())
        record = device_record(camera)
        assert not camera.present and record["status"] == "offline"
        assert record["last_seen"].startswith("1970-01-01T00:16:40"), "last_seen stays the last packet time"
        assert record["snapshot_at"] > record["last_seen"], "a newer snapshot lets the API accept the change"
        assert camera.status == "normal", "presence never enters saved enforcement state"

        clock.advance(5)
        poll(discovery, {CAMERA})
        assert camera.present and device_record(camera)["status"] == "normal"
        assert kinds(directory).count("device_offline") == 1
        assert kinds(directory).count("device_online") == 1


def test_announced_leave_goes_offline_after_short_grace_and_join_is_immediate():
    with tempfile.TemporaryDirectory() as directory:
        clock = DemoClock(1000)
        agent, discovery = setup(directory, clock)
        camera = agent.inventory.get(CAMERA)
        camera.last_seen = 1000
        poll(discovery, {CAMERA, "02:00:00:00:00:02"})

        assert ap_event(discovery, CAMERA, joined=False) is False
        clock.advance(DemoDiscovery.LEAVE_GRACE - 1)
        assert discovery.tick() is False and camera.present
        clock.advance(1)
        assert discovery.tick() is True, "a presence change asks for an immediate upload"
        assert device_record(camera)["status"] == "offline"
        assert kinds(directory)[-1] == "device_offline"

        assert ap_event(discovery, CAMERA, joined=True) is True
        assert device_record(camera)["status"] == "normal"


def test_poll_taken_before_a_leave_event_does_not_undo_it():
    with tempfile.TemporaryDirectory() as directory:
        clock = DemoClock(1000)
        agent, discovery = setup(directory, clock)
        camera = agent.inventory.get(CAMERA)
        camera.last_seen = 1000
        poll(discovery, {CAMERA})
        stale = time.monotonic()
        ap_event(discovery, CAMERA, joined=False)
        poll(discovery, {CAMERA}, taken_at=stale)  # still lists the camera, but is older
        clock.advance(DemoDiscovery.LEAVE_GRACE)
        discovery.tick()
        assert not camera.present


def test_live_loop_uploads_immediately_when_presence_changes():
    from securiot_agent.live import LivePump

    class Cloud:
        ticks = 0
        def tick(self):
            self.ticks += 1
            return []

    class Discovery:
        result = False
        def tick(self):
            return self.result

    with tempfile.TemporaryDirectory() as directory:
        agent, collector = build(ROOT / "agent/fixtures/devices.json", Path(directory), clock=DemoClock(1000))
        cloud, discovery = Cloud(), Discovery()
        pump = LivePump(agent, collector, cloud, discovery=discovery)
        pump.step(100.0, wait=0)
        pump.step(100.5, wait=0)
        assert cloud.ticks == 1, "normally one cloud cycle per 2 seconds"
        discovery.result = True
        pump.step(100.6, wait=0)
        assert cloud.ticks == 2


def test_quarantine_is_reported_over_presence():
    with tempfile.TemporaryDirectory() as directory:
        clock = DemoClock(1000)
        agent, discovery = setup(directory, clock)
        camera = agent.inventory.get(CAMERA)
        camera.last_seen = 1000
        camera.status = "quarantined"
        poll(discovery, set())
        clock.advance(DemoDiscovery.OFFLINE_AFTER)
        poll(discovery, set())
        assert not camera.present
        assert device_record(camera)["status"] == "quarantined"


def test_unknown_presence_never_marks_offline():
    with tempfile.TemporaryDirectory() as directory:
        clock = DemoClock(1000)
        agent, discovery = setup(directory, clock)
        poll(discovery, None)
        clock.advance(DemoDiscovery.OFFLINE_AFTER * 4)
        poll(discovery, None)
        assert all(device.present for device in agent.inventory.devices.values())


def test_device_outside_wifi_subnet_is_ignored():
    with tempfile.TemporaryDirectory() as directory:
        clock = DemoClock(1000)
        agent, discovery = setup(directory, clock)
        laptop = agent.inventory.get("02:00:00:00:00:02")
        laptop.ip = "169.254.45.162"  # management link, never a Wi-Fi station
        poll(discovery, set())
        clock.advance(DemoDiscovery.OFFLINE_AFTER * 2)
        poll(discovery, set())
        assert laptop.present


def test_device_that_left_before_a_restart_can_still_be_reported_offline():
    with tempfile.TemporaryDirectory() as directory:
        clock = DemoClock(1000)
        agent, discovery = setup(directory, clock)
        agent.inventory.get(CAMERA).last_seen = 1000
        discovery.close()  # saves presence.json, as when the service stops

        clock.advance(600)
        agent, discovery = setup(directory, clock)  # restarted while the camera is gone
        camera = agent.inventory.get(CAMERA)
        assert camera.last_seen == 1000, "last packet time survives the restart"
        poll(discovery, set())
        clock.advance(DemoDiscovery.OFFLINE_AFTER)
        poll(discovery, set())
        record = device_record(camera)
        assert record is not None and record["status"] == "offline"
        assert record["last_seen"].startswith("1970-01-01T00:16:40")


def test_restart_keeps_an_offline_device_offline_until_it_reassociates():
    with tempfile.TemporaryDirectory() as directory:
        clock = DemoClock(1000)
        agent, discovery = setup(directory, clock)
        agent.inventory.get(CAMERA).last_seen = 1000
        poll(discovery, set())
        clock.advance(DemoDiscovery.OFFLINE_AFTER)
        poll(discovery, set())  # marked offline and saved on this tick

        clock.advance(60)
        agent, discovery = setup(directory, clock)  # agent restarts
        camera = agent.inventory.get(CAMERA)
        assert device_record(camera)["status"] == "offline", "no flicker back onto the dashboard"
        poll(discovery, {CAMERA})
        assert device_record(camera)["status"] == "normal"


def test_guest_saved_before_presence_file_existed_uses_discovery_file_time():
    with tempfile.TemporaryDirectory() as directory:
        Path(directory, "discovered-devices.json").write_text(json.dumps(
            {"version": 1, "devices": [{"mac": "02:00:00:00:00:77", "ip": "10.42.0.77", "name": None}]}))
        clock = DemoClock(5000)
        agent, discovery = setup(directory, clock)
        guest = agent.inventory.get("02:00:00:00:00:77")
        assert guest is not None and guest.last_seen is not None
        poll(discovery, set())
        clock.advance(DemoDiscovery.OFFLINE_AFTER)
        poll(discovery, set())
        assert device_record(guest)["status"] == "offline"


def test_packet_from_device_brings_it_back_immediately():
    with tempfile.TemporaryDirectory() as directory:
        clock = DemoClock(1000)
        agent, discovery = setup(directory, clock)
        camera = agent.inventory.get(CAMERA)
        poll(discovery, set())
        clock.advance(DemoDiscovery.OFFLINE_AFTER)
        poll(discovery, set())
        assert not camera.present
        discovery.register(CAMERA, "10.42.0.20", None, "captured_source", seen=True)
        assert camera.present
