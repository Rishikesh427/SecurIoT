"""Accept-and-close decoys. No credentials, exploit input, or shell execution."""
import argparse
import asyncio
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path

from .replay import load_devices

DEFAULT_PORTS = (23, 2323, 80, 445, 554, 8080)


def mapping(devices_path):
    result = {}
    if devices_path is not None:
        for device in load_devices(devices_path).devices.values():
            ip = str(ipaddress.ip_address(device.ip))
            if ip in result:
                raise ValueError("Duplicate configured IP; MAC attribution would be ambiguous")
            result[ip] = device.mac
    return result


async def start_decoys(bind, ports, *, known_ips=None, on_hit=None):
    address = ipaddress.ip_address(bind)
    if address.is_unspecified or address.is_multicast:
        raise ValueError("Bind an explicit assigned unicast decoy IP, not a wildcard")
    known_ips = known_ips or {}
    ports = list(ports)
    if len(set(ports)) != len(ports) or any(type(p) is not int or not 0 <= p <= 65535 for p in ports):
        raise ValueError("Ports must be unique integers; zero is reserved for library tests")
    def emit(record):
        if on_hit is not None:
            on_hit(record)
        else:
            print(json.dumps(record), flush=True)
    async def hit(reader, writer):
        try:
            peer = writer.get_extra_info("peername")
            local = writer.get_extra_info("sockname")
            ip = str(ipaddress.ip_address(peer[0]))
            emit({"kind":"decoy_connection", "ts":datetime.now(timezone.utc).isoformat(),
                  "peer_ip":ip, "port":local[1], "bind_ip":local[0],
                  "mapped_mac":known_ips.get(ip),
                  "identity_source":"configured_ip_mapping" if ip in known_ips else "unknown",
                  "mac_observed_in_packet":False, "simulated_service":True})
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
    servers = []
    try:
        for port in ports:
            servers.append(await asyncio.start_server(hit, str(address), port))
        return servers
    except BaseException:
        for server in servers:
            server.close()
        await asyncio.gather(*(server.wait_closed() for server in servers))
        raise


async def serve(args):
    known_ips = mapping(args.devices)
    servers = []
    try:
        for bind in args.bind:
            servers.extend(await start_decoys(bind,args.ports,known_ips=known_ips))
        print(json.dumps({"kind":"decoy_ready","binds":args.bind,"ports":args.ports,
                          "note":"Packet MAC attribution/detection comes from --live IFACE --decoy-ip IP."}),flush=True)
        await asyncio.gather(*(server.serve_forever() for server in servers))
    finally:
        for server in servers:
            server.close()
        await asyncio.gather(*(server.wait_closed() for server in servers))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind",required=True,action="append",help="Assigned decoy IP; repeat for a second IP.")
    parser.add_argument("--ports",type=int,nargs="+",default=list(DEFAULT_PORTS))
    parser.add_argument("--devices",type=Path,help="Known-device JSON for explicitly labeled IP-to-MAC mapping.")
    args = parser.parse_args()
    if not args.ports or any(not 1 <= p <= 65535 for p in args.ports):
        parser.error("CLI ports must be from 1 to 65535")
    try:
        asyncio.run(serve(args))
    except KeyboardInterrupt:
        pass
    except (ValueError, OSError) as error:
        parser.exit(1, f"Decoy startup failed: {error}\n")
