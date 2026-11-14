import argparse
from pathlib import Path
import sys
import os

from .simulation import run_demo
from .cloud import CloudError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the SecurIoT agent with mock enforcement.")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--simulate", action="store_true",
                      help="Walk through synthetic summary observations.")
    mode.add_argument("--replay", type=Path, metavar="CAPTURE",
                      help="Read Ethernet packets from an offline PCAP/PCAPNG file.")
    mode.add_argument("--live", metavar="IFACE",
                      help="Sniff a live interface (needs root). Enforcement stays mocked.")
    parser.add_argument("--devices", type=Path,
                        default=Path(__file__).resolve().parents[1] / "fixtures" / "devices.json",
                        help="Known-device JSON for replay (default: generated fixture devices).")
    parser.add_argument("--detector", choices=("ml", "preview"), default="ml",
                        help="Replay detector: Worker C's package (default) or the legacy preview.")
    parser.add_argument("--model-mode", choices=("required", "auto", "rules"), default="required", help="Require the trained artifact by default; auto reports fallback, rules explicitly disables it.")
    parser.add_argument("--arm", action="store_true",
                        help="Explicitly allow mock actions during the walkthrough; learning mode is the default.")
    parser.add_argument("--state-dir", type=Path,
                        help="Local state/outbox directory (default: agent/runtime, with replay in a subfolder).")
    parser.add_argument("--decoy-ip", action="append", default=[], help="Explicitly configured decoy destination IP (repeatable).")
    parser.add_argument("--connect", action="store_true", help="Upload replay results and poll cloud commands continuously.")
    parser.add_argument("--api-url", default=os.environ.get("SECURIOT_API_URL"))
    parser.add_argument("--once", action="store_true", help="One final cloud cycle after replay, then exit.")
    parser.add_argument("--detector-factory", help="Explicit module:factory for C's future trained-model adapter.")
    args = parser.parse_args(argv)
    if args.connect and (not args.replay or args.detector != "ml" or not args.api_url or not os.environ.get("AGENT_API_KEY")):
        parser.error("--connect requires --replay, --detector ml, --api-url, and AGENT_API_KEY in the environment")
    if (args.once or args.detector_factory) and not args.connect:
        parser.error("--once and --detector-factory require --connect")
    runtime_dir = Path(__file__).resolve().parents[1] / "runtime"
    state_dir = args.state_dir or (runtime_dir / "connected" if args.connect else runtime_dir / "replay" if args.replay else runtime_dir)
    try:
        if args.connect:
            from .runner import run_connected
            run_connected(args.replay, args.devices, state_dir, args.api_url, os.environ["AGENT_API_KEY"],
                          armed=args.arm, once=args.once, detector_factory=args.detector_factory, decoy_ips=args.decoy_ip, model_mode=args.model_mode)
        elif args.replay:
            # Keep the original summary demo usable without the optional Scapy install.
            from .replay import run_replay

            run_replay(args.replay, args.devices, state_dir, args.arm, args.detector, args.decoy_ip, args.model_mode)
        elif args.live:
            from .live import run_live

            run_live(args.live, args.devices, runtime_dir / "live" if not args.state_dir else args.state_dir,
                     args.arm, args.decoy_ip, args.model_mode)
        else:
            run_demo(state_dir, args.arm)
    except ModuleNotFoundError as error:
        if error.name == "jsonschema":
            print('Cloud runner needs: python3 -m pip install -e "agent[cloud,replay]"', file=sys.stderr)
            return 1
        if error.name and error.name.startswith("scapy"):
            print('Packet replay needs Scapy. Install with: python3 -m pip install -e "agent[replay]"',
                  file=sys.stderr)
            return 1
        if error.name and error.name.startswith("securiot_ml"):
            print('Worker C integration needs: python3 -m pip install -e ./ml', file=sys.stderr)
            return 1
        raise
    except (OSError, ValueError, CloudError) as error:
        print(f"Agent stopped: {error}", file=sys.stderr)
        return 1
    return 0
