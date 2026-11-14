"""Build an isolated API/React stack, verify model->cloud->Restore, then remove it.

Run: agent/.venv/bin/python agent/tools/smoke_stack.py
Uses only ephemeral demo credentials and SQLite memory storage, never your DB.
"""
from pathlib import Path
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "agent"), str(ROOT)]


def main():
    if shutil.which("docker") is None:
        raise SystemExit("Docker CLI is required")
    import httpx
    from securiot_agent.cloud import CloudClient, CloudError
    from securiot_agent.cloud_loop import CloudLoop
    from securiot_agent.runner import run_connected
    project = "securiot-smoke-" + secrets.token_hex(4)
    with tempfile.TemporaryDirectory(prefix="securiot-stack-") as directory:
        directory = Path(directory)
        key, password, jwt = (secrets.token_urlsafe(36) for _ in range(3))
        env_file = directory / "settings.env"
        env_file.write_text(f"SMOKE_AGENT_KEY={key}\nSMOKE_JUDGE_PASSWORD={password}\nSMOKE_JWT_SECRET={jwt}\n")
        env_file.chmod(0o600)
        override = directory / "compose.smoke.yaml"
        override.write_text("""services:
  api:
    env_file: !reset []
    environment:
      APP_ENV: development
      ROOT_PATH: /api
      STORAGE_MODE: memory
      DATABASE_URL: ""
      WEB_CONCURRENCY: "1"
      JWT_SECRET: ${SMOKE_JWT_SECRET}
      AGENT_API_KEY: ${SMOKE_AGENT_KEY}
      JUDGE_USERNAME: smoke
      JUDGE_PASSWORD: ${SMOKE_JUDGE_PASSWORD}
  caddy:
    environment:
      SITE_ADDRESS: ":80"
    ports: !override
      - "127.0.0.1::80"
""")
        command = ["docker", "compose", "--project-name", project, "--env-file", str(env_file),
                   "-f", str(ROOT / "compose.yaml"), "-f", str(override)]
        try:
            subprocess.run(command + ["config", "--quiet"], cwd=ROOT, check=True)
            print("Building isolated demo stack", project, flush=True)
            subprocess.run(command + ["up", "--build", "-d", "--wait", "--wait-timeout", "180"], cwd=ROOT, check=True)
            address = subprocess.check_output(command + ["port", "caddy", "80"], cwd=ROOT, text=True).strip()
            if not re.fullmatch(r"127\.0\.0\.1:\d+", address):
                raise ValueError("Smoke stack must bind only to loopback")
            origin = "http://" + address
            with httpx.Client(base_url=origin, timeout=10) as http:
                page = http.get("/")
                page.raise_for_status()
                assert 'id="root"' in page.text
                assets = re.findall(r'(?:src|href)="(/assets/[^"]+)"', page.text)
                assert assets and all(http.get(asset).status_code == 200 for asset in assets)
                assert http.get("/api/healthz").status_code == 200
                storage = http.get("/api/storage").json()
                assert storage["mode"] == "memory" and storage["demo_storage"]
                login = http.post("/api/auth/login", json={"username":"smoke", "password":password})
                login.raise_for_status()
                headers = {"Authorization":"Bearer " + login.json()["access_token"]}
                policy = {"learning_mode":False,"protected_macs":[],
                          "ladder":{"notify":True,"block_wan":True,"quarantine":True}}
                http.put("/api/policy",json=policy,headers=headers).raise_for_status()
                url = origin + "/api"
                result = run_connected(ROOT / "agent/fixtures/arp_scan.pcap",
                    ROOT / "agent/fixtures/devices.json", directory / "agent-state", url, key,
                    armed=True, once=True, model_mode="required")
                assert result.agent.detector.model_status["active"]
                assert result.agent.detector.model_status["predictions"] > 0
                mac = "02:00:00:00:00:20"
                devices = http.get("/api/devices",headers=headers).json()
                assert next(d for d in devices if d["mac"] == mac)["status"] == "quarantined"
                count = len(http.get("/api/events",headers=headers).json())
                class Lossy:
                    def __init__(self):
                        self.client = CloudClient(url,key)
                        self.identity = self.client.identity
                        self.drop_ingest = self.drop_ack = True
                    def request(self, method, path, payload=None, query=None):
                        response = self.client.request(method,path,payload,query)
                        if path == "/ingest" and self.drop_ingest:
                            self.drop_ingest = False
                            raise CloudError("test: accepted ingest response lost")
                        if path.endswith("/ack") and self.drop_ack:
                            self.drop_ack = False
                            raise CloudError("test: accepted ack response lost")
                        return response
                transport = Lossy()
                loop = CloudLoop(result.agent, transport, ROOT / "contract/schemas.json", permit_arm=True)
                assert loop.tick()  # The already accepted event batch remains frozen for retry.
                assert loop.tick() == []
                assert len(http.get("/api/events",headers=headers).json()) == count
                request_headers = {**headers,"Idempotency-Key":str(uuid4())}
                action = http.post("/api/actions",json={"action":"restore","mac":mac},headers=request_headers)
                action.raise_for_status()
                duplicate = http.post("/api/actions",json={"action":"restore","mac":mac},headers=request_headers)
                assert duplicate.json()["id"] == action.json()["id"]
                assert loop.tick()  # Restore succeeded, acknowledgement reply intentionally lost.
                grace = result.agent.grace_until[mac]
                restarted = CloudLoop(result.agent, transport, ROOT / "contract/schemas.json", permit_arm=True)
                assert restarted.tick() == []
                assert result.agent.grace_until[mac] == grace
                assert result.agent.enforcer.calls.count(("restore",mac)) == 1
                devices = http.get("/api/devices",headers=headers).json()
                assert next(d for d in devices if d["mac"] == mac)["status"] == "normal"
                assert CloudClient(url,key).request("GET","/sync")[1]["commands"] == []
                print(json.dumps({"frontend_assets_served":True,"api_health":True,"storage":"isolated memory",
                    "trained_model_loaded":True,"model_predictions":result.agent.detector.model_status["predictions"],
                    "events_uploaded":count,"restore_acknowledged":True,"event_retry_deduplicated":True,
                    "restore_not_repeated_after_ack_loss":True},indent=2),flush=True)
        finally:
            subprocess.run(command + ["down", "--volumes", "--remove-orphans"], cwd=ROOT, check=False)
            print("Removed isolated smoke containers and volumes; other stacks were not modified.",flush=True)


if __name__ == "__main__":
    main()
