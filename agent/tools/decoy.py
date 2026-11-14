"""Decoy listener. No legitimate device connects to it, so any hit is suspicious.

Run on the router laptop. Give it an unused IP on the hotspot network first (see steps),
then pass the same IP to the agent with --decoy-ip. Accepts and immediately closes
connections; it never sends data or runs anything.
"""
import argparse, asyncio, time

async def hit(reader, writer):
    peer = writer.get_extra_info("peername")
    port = writer.get_extra_info("sockname")[1]
    print(f"{time.strftime('%H:%M:%S')} DECOY HIT port {port} from {peer[0]}", flush=True)
    writer.close()

async def main(a):
    servers = [await asyncio.start_server(hit, a.bind, p) for p in a.ports]
    print(f"Decoy listening on {a.bind} ports {a.ports}", flush=True)
    await asyncio.gather(*(s.serve_forever() for s in servers))

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", required=True, help="the decoy IP (an alias on the hotspot interface)")
    ap.add_argument("--ports", type=int, nargs="+", default=[23, 2323, 445, 554, 8080])
    asyncio.run(main(ap.parse_args()))
