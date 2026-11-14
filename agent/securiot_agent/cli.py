import argparse
from pathlib import Path
import sys

from .simulation import run_demo


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the SecurIoT agent with mock enforcement.")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--simulate", action="store_true",
                      help="Walk through synthetic summary observations.")
    mode.add_argument("--replay", type=Path, metavar="CAPTURE",
                      help="Read Ethernet packets from an offline PCAP/PCAPNG file.")
    parser.add_argument("--devices", type=Path,
                        default=Path(__file__).resolve().parents[1] / "fixtures" / "devices.json",
                        help="Known-device JSON for replay (default: generated fixture devices).")
    parser.add_argument("--detector", choices=("ml", "preview"), default="ml",
                        help="Replay detector: Worker C's package (default) or the legacy preview.")
    parser.add_argument("--arm", action="store_true",
                        help="Explicitly allow mock actions during the walkthrough; learning mode is the default.")
    parser.add_argument("--state-dir", type=Path,
                        help="Local state/outbox directory (default: agent/runtime, with replay in a subfolder).")
    args = parser.parse_args(argv)
    runtime_dir = Path(__file__).resolve().parents[1] / "runtime"
    state_dir = args.state_dir or (runtime_dir / "replay" if args.replay else runtime_dir)
    try:
        if args.replay:
            # Keep the original summary demo usable without the optional Scapy install.
            from .replay import run_replay

            run_replay(args.replay, args.devices, state_dir, args.arm, args.detector)
        else:
            run_demo(state_dir, args.arm)
    except ModuleNotFoundError as error:
        if error.name and error.name.startswith("scapy"):
            print('Packet replay needs Scapy. Install with: python3 -m pip install -e "agent[replay]"',
                  file=sys.stderr)
            return 1
        if error.name and error.name.startswith("securiot_ml"):
            print('Worker C integration needs: python3 -m pip install -e ./ml', file=sys.stderr)
            return 1
        raise
    except (OSError, ValueError) as error:
        print(f"Agent stopped: {error}", file=sys.stderr)
        return 1
    return 0
