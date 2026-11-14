"""Step 11 regression tests; use python -m pytest agent/tests/test_routine.py."""
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from securiot_agent.models import Device, Observation, Finding
from securiot_agent.routine import Routine, atomic

MAC='02:00:00:00:00:01'

class RoutineTests(unittest.TestCase):
    def setUp(self):
        self.temp=TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)
        self.r=Routine(self.path,'simulation',0)
        self.device=Device(MAC,'10.42.0.2','Test')
        self.devices={MAC:self.device}
    def record(self, now, nbytes=1000, clean=True, **extra):
        self.r.record(Observation(MAC,bytes_out=nbytes,**extra),now,clean)
    def calibrate(self):
        atomic(self.r.command, {'macs':[MAC]})
        self.r.advance(0,self.devices,True)
        self.record(0)
        for i in range(1,32):
            self.r.advance(i*10,self.devices,True)
            if i<31: self.record(i*10)
    def test_no_automatic_calibration(self):
        self.record(0)
        self.r.advance(10,self.devices,True)
        self.assertEqual(self.r.state['baselines'],{})
    def test_freezes_after_30_complete_windows_and_persists(self):
        self.calibrate()
        b=self.r.state['baselines'][MAC]
        self.assertEqual(b['samples'],30)
        self.assertEqual(b['mean'],1000)
        self.assertEqual(b['std'],0)
        restored=Routine(self.path,'simulation',311)
        self.assertEqual(restored.state['baselines'][MAC],b)
        self.assertNotIn(MAC,restored.state['calibrating'])
    def test_armed_mode_pauses_training(self):
        self.r.state['calibrating'][MAC]=[]
        self.record(0)
        self.r.advance(10,self.devices,False)
        self.record(10)
        self.r.advance(20,self.devices,False)
        self.assertEqual(self.r.state['calibrating'][MAC],[])
    def test_partial_and_tainted_windows_do_not_train(self):
        self.r.state['calibrating'][MAC]=[]
        self.record(4)
        self.r.advance(10,self.devices,True)
        self.record(11,packet_decoy_hits=(23,))
        self.r.advance(20,self.devices,True)
        self.assertEqual(self.r.state['calibrating'][MAC],[])
        self.record(20)
        self.r.advance(30,self.devices,True)
        self.assertEqual(self.r.state['calibrating'][MAC],[1000])
    def test_detection_and_recent_signal_excluded(self):
        self.r.state['calibrating'][MAC]=[]
        self.record(0)
        self.r.advance(10,self.devices,True)
        self.record(10)
        self.r.flag(MAC)
        self.r.signal(MAC,1,11)
        self.r.advance(20,self.devices,True)
        self.assertEqual(self.r.state['calibrating'][MAC],[])
    def test_volume_uses_full_window_and_handles_constant_baseline(self):
        self.calibrate()
        # Window 310-320 receives a large transfer. Earlier windows unchanged.
        self.record(311,10000)
        self.assertEqual(self.r.advance(319,self.devices,False),[])
        events=self.r.advance(320,self.devices,False)
        self.assertEqual(len(events),1)
        self.assertTrue(events[0][2]['advisory_only'])
        self.assertEqual(events[0][2]['window_seconds'],10)
        self.assertEqual(self.r.state['baselines'][MAC]['mean'],1000)
    def test_expiry_survives_restart(self):
        self.r.signal(MAC,.9,10)
        restored=Routine(self.path,'simulation',100)
        self.assertEqual(restored.scores(309)[MAC],.9)
        self.assertEqual(restored.scores(310),{})
    def test_latest_detection_renews_expiry(self):
        self.r.signal(MAC,.9,10)
        self.r.signal(MAC,.3,200)
        self.assertEqual(self.r.scores(499)[MAC],.9)
        self.assertEqual(self.r.scores(500),{})
    def test_clock_rollback_discards_future_signal(self):
        self.r.signal(MAC,.9,100)
        self.assertEqual(Routine(self.path,'simulation',90).scores(90),{})
    def test_restart_does_not_count_incomplete_window(self):
        self.r.state['calibrating'][MAC]=[1000]
        self.r.dirty=True
        self.record(5)
        self.r.save(5,force=True)
        restored=Routine(self.path,'simulation',8)
        self.assertEqual(restored.windows,{})
        self.assertEqual(restored.state['calibrating'][MAC],[1000])
    def test_long_gap_is_not_fabricated_idle_samples(self):
        self.r.state['calibrating'][MAC]=[]
        self.record(0)
        self.r.advance(100,self.devices,True)
        self.assertEqual(self.r.state['calibrating'][MAC],[])
    def test_wrong_mode_and_malformed_state_rejected(self):
        self.r.signal(MAC,.9,10)
        with self.assertRaises(ValueError): Routine(self.path,'linux',20)
        state=json.loads(self.r.path.read_text())
        state['signals'][MAC]['score']=2
        atomic(self.r.path,state)
        with self.assertRaises(ValueError): Routine(self.path,'simulation',20)
    def test_volume_survives_wire_and_digest(self):
        from securiot_agent.models import Event
        from securiot_agent.wire import event_record
        from api.audit_history import merge_history
        from securiot_ml.digest import digest
        ev=Event.at(100,mac=MAC,kind='detection',evidence={
            'finding':'volume','decision':'supporting_evidence_only'},simulated=True)
        wire=event_record(ev.to_dict())
        self.assertEqual(wire['kind'],'volume')
        summary=digest(merge_history([], [wire]))['summary']
        self.assertIn('1 detection(s)',summary)
        self.assertIn('Simulator activity',summary)
    def test_runtime_idle_expiry_preserves_restriction_and_last_seen(self):
        from securiot_agent.runtime import Agent
        from securiot_agent.inventory import Inventory
        from securiot_agent.enforcement import MockEnforcer
        from securiot_agent.storage import Storage
        class Detector:
            anomaly={}
            def assess_device(self,device):
                score=round(self.anomaly.get(device.mac,0)*40)
                return dict(type='unknown',risk=score,band='medium' if score>=30 else 'low',
                            confidence='n/a',reasons=[])
            def observe(self,observation): return None
        now=[100.]
        agent=Agent(Inventory([self.device]),Detector(),MockEnforcer(),Storage(self.path),clock=lambda:now[0])
        self.device.last_seen=90
        self.device.status='quarantined'
        agent.routine.signal(MAC,1,100)
        agent.routine_tick()
        self.assertEqual(self.device.assessment['risk'],40)
        now[0]=400
        agent.routine_tick()
        self.assertEqual(self.device.assessment['risk'],0)
        self.assertEqual(self.device.last_seen,90)
        self.assertEqual(self.device.status,'quarantined')
        self.assertEqual(self.device.snapshot_at,400)

if __name__=='__main__': unittest.main()
