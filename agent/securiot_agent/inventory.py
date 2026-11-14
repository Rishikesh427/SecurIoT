"""Known devices and their observed traffic."""

from .models import Device, Observation, normalize_mac


class Inventory:
    def __init__(self, devices: list[Device]):
        self.devices: dict[str, Device] = {}
        for device in devices:
            if device.mac in self.devices:
                raise ValueError(f"Duplicate device: {device.mac}")
            self.devices[device.mac] = device

    def get(self, mac: str) -> Device | None:
        return self.devices.get(normalize_mac(mac))

    def observe(self, observation: Observation, now: float) -> Device | None:
        device = self.get(observation.mac)
        if device is not None:
            device.bytes_in += observation.bytes_in
            device.bytes_out += observation.bytes_out
            destinations = set(observation.destinations)
            destinations.update(ip for ip, _ in observation.syn_targets)
            device.dests = sorted(set(device.dests) | destinations)
            device.dns_queries = sorted(set(device.dns_queries) | set(observation.dns_queries))
            device.last_seen = now
        return device
