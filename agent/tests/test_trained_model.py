"""Actual arrived artifact integration plus deterministic cadence/guard tests."""
import copy
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
from uuid import uuid4

import numpy as np
import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "agent"), str(ROOT)]
from api.main import create_app
from api.settings import Settings
from securiot_ml.model import FEATS, Window
from securiot_ml.detect import MODEL_PATH
from securiot_agent.cloud import CloudError
from securiot_agent.cloud_loop import CloudLoop
from securiot_agent.ml_adapter import MLAdapter
from securiot_agent.models import Observation
from securiot_agent.replay import load_devices, replay_capture
from securiot_agent.simulation import DemoClock
from securiot_agent.storage import Storage
from securiot_agent.trained import TrainedScanModel

MAC = "02:00:00:00:00:20"


def required():
    clock = DemoClock(1000)
    adapter = MLAdapter(clock, model_mode="required")
    return clock, adapter


def test_actual_artifact_is_loaded_with_matching_features_and_labels():
    _, adapter = required()
    assert adapter.model_status["active"]
    assert adapter.model_status["features"] == list(adapter.trained.model.feature_names_in_)
    assert set(adapter.model_status["features"]) <= set(FEATS)
    assert len(adapter.model_status["sha256"]) == 64
    assert adapter.model_status["threshold"] >= .9
    assert adapter.detector.model is None  # Only the cadence-correct path can predict.
    assert adapter.trained.model is not None


def test_actual_replay_executes_real_model_predictions():
    with tempfile.TemporaryDirectory() as directory:
        result = replay_capture(ROOT / "agent/fixtures/arp_scan.pcap",
            load_devices(ROOT / "agent/fixtures/devices.json"), Storage(Path(directory)),
            detector="ml", model_mode="required", armed=True)
        status = result.agent.detector.model_status
        assert status["active"] and status["predictions"] > 0
        assert result.agent.inventory.get(MAC).status == "quarantined"


def test_actual_feature_vectors_match_training_window_and_ignore_incoming_frames():
    clock, adapter = required()
    seen = []
    real_model = adapter.trained.model
    class Spy:
        def predict_proba(self, frame):
            seen.append(frame.iloc[0].tolist())
            return real_model.predict_proba(frame)
    adapter.trained.model = Spy()
    reference = Window()
    expected = []
    samples = [
        Observation(MAC, bytes_out=60, captured_at=1000, packet_syn_targets=(("10.42.0.50",80),)),
        Observation(MAC, bytes_out=80, captured_at=1031, packet_syn_targets=(("10.42.0.51",23),)),
        Observation(MAC, bytes_out=40, captured_at=1031.5, packet_arp_requests=1, arp_targets=("10.42.0.1",)),
        Observation(MAC, bytes_out=100, captured_at=1032, packet_syn_targets=(("10.42.0.52",80),)),
    ]
    for index, observation in enumerate(samples):
        vector = reference.add(observation.captured_at, observation.packet_arp_requests,
                               observation.packet_syn_targets, observation.bytes_out)
        if index in (1,3):
            expected.append(vector)
        clock.now = observation.captured_at
        adapter.observe(observation)
        if index == 1:
            adapter.observe(Observation(MAC, bytes_in=5000, captured_at=1031.2))
    selected = adapter.model_status["features"]
    assert seen == [[row[FEATS.index(name)] for name in selected] for row in expected]


class PositiveModel:
    classes_ = np.array([0,1])
    feature_names_in_ = np.array(FEATS)
    def predict_proba(self, frame):
        return np.array([[.01,.99]])


def controlled():
    clock, adapter = required()
    adapter.trained.model = PositiveModel()
    clock.advance(31)
    w = Window()
    w.add(1030, 0, [(f"10.42.0.{i}", 80) for i in range(50,58)], 60)
    adapter.trained.windows[MAC] = w
    return clock, adapter


def test_two_packets_in_one_second_are_not_two_consecutive_windows():
    clock, adapter = controlled()
    for fraction in (0, .1, .2, .8):
        assert adapter.observe(Observation(MAC, bytes_out=60, captured_at=1031+fraction)) is None
    clock.advance(1)
    result = adapter.observe(Observation(MAC, bytes_out=60, captured_at=1032))
    assert result.evidence["basis"] == "trained_scan_model"
    assert not result.containment_allowed
    assert adapter.model_status["predictions"] == 2


def test_gap_between_observed_seconds_resets_model_streak():
    clock, adapter = controlled()
    assert adapter.observe(Observation(MAC, bytes_out=60, captured_at=1031)) is None
    clock.advance(3)
    assert adapter.observe(Observation(MAC, bytes_out=60, captured_at=1034)) is None


def test_required_model_fails_and_auto_mode_reports_fallback():
    missing = SimpleNamespace(model=None)
    with pytest.raises(ValueError, match="Trained model unavailable"):
        TrainedScanModel("required", missing, MODEL_PATH)
    fallback = TrainedScanModel("auto", missing, MODEL_PATH)
    assert fallback.status["active"] is False and fallback.status["reason"]


def test_feature_order_mismatch_cannot_silently_predict():
    wrong = SimpleNamespace(model=PositiveModel(), feats=list(reversed(FEATS)), thr=.95)
    with pytest.raises(ValueError, match="feature order"):
        TrainedScanModel("required", wrong, MODEL_PATH)


def test_saved_threshold_cannot_bypass_local_floor():
    low = SimpleNamespace(model=PositiveModel(), feats=FEATS, thr=.1)
    assert TrainedScanModel("required", low, MODEL_PATH).threshold == .9


def test_invalid_probability_stops_before_action():
    clock, adapter = controlled()
    class Invalid:
        def predict_proba(self, frame):
            return np.array([[0, float("nan")]])
    adapter.trained.model = Invalid()
    with pytest.raises(ValueError, match="invalid probability"):
        adapter.observe(Observation(MAC, bytes_out=60, captured_at=1031))


def test_real_model_api_memory_database_login_restore_and_ack():
    config = Settings(database_url="", jwt_secret="test-only-secret-"*3, agent_api_key="test-key",
                      storage_mode="memory", judge_username="judge", judge_password="test-only-password-12345")
    with tempfile.TemporaryDirectory() as directory, TestClient(create_app(config)) as http:
        login = http.post("/auth/login", json={"username":"judge","password":config.judge_password})
        assert login.status_code == 200
        headers = {"Authorization":"Bearer " + login.json()["access_token"]}
        result = replay_capture(ROOT / "agent/fixtures/arp_scan.pcap",
            load_devices(ROOT / "agent/fixtures/devices.json"), Storage(Path(directory)),
            detector="ml", model_mode="required", armed=True)
        class Transport:
            identity = "real-memory-api"
            def request(self, method, path, payload=None, query=None):
                response = http.request(method,path,json=payload,params=query,headers={"X-API-Key":"test-key"})
                if response.status_code not in (200,204,304):
                    raise CloudError(f"HTTP {response.status_code}")
                return response.status_code, response.json() if response.status_code == 200 else None
        loop = CloudLoop(result.agent, Transport(), ROOT / "contract/schemas.json", permit_arm=True)
        assert loop.tick() == []
        devices = http.get("/devices",headers=headers).json()
        assert next(d for d in devices if d["mac"] == MAC)["status"] == "quarantined"
        action = http.post("/actions",json={"action":"restore","mac":MAC},
            headers={**headers,"Idempotency-Key":str(uuid4())})
        assert action.status_code == 202
        result.agent.clock.advance(2)
        assert loop.tick() == []
        assert result.agent.inventory.get(MAC).status == "normal"
        assert http.get("/sync",headers={"X-API-Key":"test-key"}).json()["commands"] == []
        assert next(d for d in http.get("/devices",headers=headers).json() if d["mac"] == MAC)["status"] == "normal"
