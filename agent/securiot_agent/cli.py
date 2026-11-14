import argparse
from pathlib import Path
import sys
import os

from .simulation import run_demo
from .cloud import CloudError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run SecurIoT replay or live capture; real enforcement is opt-in.")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--simulate", action="store_true",
                      help="Walk through synthetic summary observations.")
    mode.add_argument("--replay", type=Path, metavar="CAPTURE",
                      help="Read Ethernet packets from an offline PCAP/PCAPNG file.")
    mode.add_argument("--live", metavar="IFACE",
                      help="Sniff a live interface (needs root). Enforcement defaults to mock.")
    parser.add_argument("--devices", type=Path,
                        default=None,
                        help="Known-device JSON. Real enforcement requires an explicit file with simulated=false.")
    parser.add_argument("--detector", choices=("ml", "preview"), default="ml",
                        help="Replay detector: Worker C's package (default) or the legacy preview.")
    parser.add_argument("--model-mode", choices=("required", "auto", "rules"), default="required", help="Require the trained artifact by default; auto reports fallback, rules explicitly disables it.")
    parser.add_argument("--arm", action="store_true",
                        help="Locally permit enforcement; cloud learning mode and protection still apply.")
    parser.add_argument("--state-dir", type=Path,
                        help="Local state/outbox directory (default: agent/runtime, with replay in a subfolder).")
    parser.add_argument("--decoy-ip", action="append", default=[], help="Explicitly configured decoy destination IP (repeatable).")
    parser.add_argument("--connect", action="store_true", help="Upload telemetry and poll dashboard commands during replay or live capture.")
    parser.add_argument("--api-url", default=os.environ.get("SECURIOT_API_URL"))
    parser.add_argument("--once", action="store_true", help="One final cloud cycle after replay, then exit.")
    parser.add_argument("--detector-factory", help="Explicit module:factory for C's future trained-model adapter.")
    parser.add_argument("--enforcement", choices=("mock", "linux"), default="mock")
    parser.add_argument("--enforcement-config", type=Path, help="Linux AP/WAN/hostapd/protected-MAC JSON.")
    mode.add_argument("--panic", action="store_true", help="After stopping the live agent, clear only SecurIoT restrictions.")
    args = parser.parse_args(argv)
    if args.connect and ((not args.replay and not args.live) or args.detector != "ml" or not args.api_url or not os.environ.get("AGENT_API_KEY")):
        parser.error("--connect requires --replay or --live, --detector ml, --api-url, and AGENT_API_KEY in the environment")
    if (args.once or args.detector_factory) and not args.connect:
        parser.error("--once and --detector-factory require --connect")
    if args.live and (args.once or args.detector_factory or args.detector != "ml"):
        parser.error("Live capture requires the built-in ml adapter and continuous polling")
    if args.enforcement == "linux" and (not (args.live or args.panic) or not args.enforcement_config or (not args.panic and args.devices is None)):
        parser.error("Linux enforcement requires --live or --panic and --enforcement-config; live also requires explicit --devices")
    if args.enforcement_config and args.enforcement != "linux":
        parser.error("--enforcement-config requires --enforcement linux")
    if args.panic and (args.enforcement != "linux" or args.connect):
        parser.error("--panic requires --enforcement linux and cannot connect to the cloud")
    args.devices = args.devices or Path(__file__).resolve().parents[1] / "fixtures" / "devices.json"
    runtime_dir = Path(__file__).resolve().parents[1] / "runtime"
    state_dir = args.state_dir or (runtime_dir / "linux" if args.enforcement == "linux" else runtime_dir / "live" if args.live else runtime_dir / "connected" if args.connect else runtime_dir / "replay" if args.replay else runtime_dir)
    try:
        config = None
        if args.enforcement == "linux":
            from .linux_enforcement import LinuxConfig
            config = LinuxConfig.load(args.enforcement_config)
        if args.panic:
            from .linux_enforcement import LinuxEnforcer
            enforcer = LinuxEnforcer(config, state_dir, [], recovery=True)
            try:
                enforcer.panic()
                print("SecurIoT restrictions cleared. Automatic containment requires a new local --arm.")
            finally:
                enforcer.close()
        elif args.live:
            from .live import run_live
            run_live(args.live, args.devices, state_dir, args.arm, args.decoy_ip, args.model_mode,
                     linux_config=config, api_url=args.api_url if args.connect else None,
                     api_key=os.environ.get("AGENT_API_KEY") if args.connect else None)
        elif args.connect:
            from .runner import run_connected
            run_connected(args.replay, args.devices, state_dir, args.api_url, os.environ["AGENT_API_KEY"],
                          armed=args.arm, once=args.once, detector_factory=args.detector_factory, decoy_ips=args.decoy_ip, model_mode=args.model_mode)
        elif args.replay:
            # Keep the original summary demo usable without the optional Scapy install.
            from .replay import run_replay

            run_replay(args.replay, args.devices, state_dir, args.arm, args.detector, args.decoy_ip, args.model_mode)
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
    except (OSError, ValueError, RuntimeError, CloudError) as error:
        print(f"Agent stopped: {error}", file=sys.stderr)
        return 1
    return 0
