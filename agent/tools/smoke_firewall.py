"""Real nftables lab in a network-isolated container; no host firewall changes."""
from pathlib import Path
import secrets
import subprocess
ROOT = Path(__file__).resolve().parents[2]


def main():
    name = "securiot-firewall-" + secrets.token_hex(4)
    try:
        subprocess.run(["docker","build","-f","agent/Dockerfile.firewall-test","-t","securiot-firewall-test","."],cwd=ROOT,check=True)
        # SYS_ADMIN permits child network namespaces. No host namespace/devices,
        # external network, writable host mount, or published ports are supplied.
        subprocess.run(["docker","run","--name",name,"--network","none","--cap-drop","ALL",
            "--cap-add","NET_ADMIN","--cap-add","NET_RAW","--cap-add","SYS_ADMIN",
            "--sysctl","net.ipv4.ip_forward=1","--sysctl","net.ipv6.conf.all.forwarding=1","--sysctl","net.ipv6.conf.default.forwarding=1",
            "--security-opt","seccomp=unconfined","-e","SECURIOT_FIREWALL_LAB=1",
            "-v",str(ROOT)+":/src:ro","securiot-firewall-test","python","agent/tools/firewall_lab_worker.py"],cwd=ROOT,check=True)
    finally:
        subprocess.run(["docker","rm","-f",name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        print("Removed only the isolated firewall lab container and its namespaces.")

if __name__ == "__main__": main()
