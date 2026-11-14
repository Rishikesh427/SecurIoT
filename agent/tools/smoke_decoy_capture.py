"""Real TCP -> live Scapy -> collector -> decoy finding, on a Docker-only network."""
import json
from pathlib import Path
import secrets
import subprocess
import time
ROOT = Path(__file__).resolve().parents[2]


def run(*args, capture=False):
    return subprocess.run(["docker",*args],cwd=ROOT,check=True,text=True,
                          stdout=subprocess.PIPE if capture else None).stdout


def main():
    suffix = secrets.token_hex(4)
    network, client, server = ("securiot-decoy-"+suffix+"-"+part for part in ("net","client","server"))
    image = "securiot-decoy-capture-test"
    try:
        run("build","-f","agent/Dockerfile.decoy-test","-t",image,".")
        run("network","create","--internal",network)
        mac = "02:00:00:00:00:20"
        run("run","-d","--name",client,"--network",network,"--mac-address",mac,image,
            "python","-c","import time; time.sleep(60)")
        def ip(container):
            return run("inspect","--format","{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",container,capture=True).strip()
        peer = ip(client)
        run("run","-d","--name",server,"--network",network,"--cap-drop","ALL","--cap-add","NET_RAW",
            "--cap-add","NET_BIND_SERVICE","-e","SECURIOT_DECOY_LAB=1","-e","PEER_IP="+peer,"-e","PEER_MAC="+mac,
            "-v",str(ROOT)+":/src:ro",image,"python","agent/tools/decoy_capture_worker.py")
        for _ in range(100):
            logs = run("logs",server,capture=True)
            if "READY" in logs:
                break
            time.sleep(.1)
        else:
            raise RuntimeError("Live decoy lab did not become ready")
        run("exec",client,"python","-c","import socket; socket.create_connection(("+repr(ip(server))+",2323),timeout=5).close()")
        code = run("wait",server,capture=True).strip()
        logs = run("logs",server,capture=True)
        print(logs)
        if code != "0" or '"actual_tcp_connection": true' not in logs:
            raise RuntimeError("Live Scapy/decoy smoke test failed")
    finally:
        for container in (server,client):
            subprocess.run(["docker","rm","-f",container],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        subprocess.run(["docker","network","rm",network],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        print("Removed only the isolated decoy lab containers/network.")

if __name__ == "__main__":
    main()
