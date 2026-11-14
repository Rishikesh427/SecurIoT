"""Internal Docker-only worker. hostapd is stubbed; nftables is real."""
import json
import os
from pathlib import Path
import sys

if os.environ.get("SECURIOT_FIREWALL_LAB") != "1":
    raise SystemExit("Only run inside the isolated firewall lab")
from securiot_agent.linux_enforcement import LinuxConfig, LinuxEnforcer
from securiot_agent.models import Device

STUB = '''#!/usr/local/bin/python
import json,sys
from pathlib import Path
p=Path('/tmp/fake-hostapd.json')
s=json.loads(p.read_text())
a=sys.argv[5:]
if a==['ping']: print('PONG')
elif a==['all_sta']: print('\\n'.join(s['stations']))
elif len(a)==2 and a[0]=='sta': print(a[1]); print('flags=[AUTH][ASSOC][AUTHORIZED]')
elif a==['deny_acl','SHOW']: print('\\n'.join(s['denied']))
else:
 if a[:2]==['deny_acl','ADD_MAC']: s['denied']=sorted(set(s['denied'])|{a[2]})
 elif a[:2]==['deny_acl','DEL_MAC']: s['denied']=[m for m in s['denied'] if m!=a[2]]
 elif a[0]=='deauthenticate': s['stations']=[m for m in s['stations'] if m!=a[1]]
 else: print('FAIL'); sys.exit(0)
 p.write_text(json.dumps(s)); print('OK')
'''


def main():
    import subprocess
    import time
    children = []
    def run(*args, check=True):
        return subprocess.run(args, check=check, capture_output=True, text=True)
    def ip(*args):
        return run("ip", *args)
    def inside(pid, *args, check=True):
        return run("nsenter", "-t", str(pid), "-n", *args, check=check)
    def ns():
        child = subprocess.Popen(["unshare", "--net", "sleep", "300"])
        children.append(child)
        for _ in range(100):
            if child.poll() is not None:
                raise RuntimeError("Cannot create isolated child network namespace")
            if os.readlink(f"/proc/{child.pid}/ns/net") != os.readlink("/proc/self/ns/net"):
                return child.pid
            time.sleep(.01)
        raise RuntimeError("Network namespace startup timed out")
    backend = None
    try:
        switch, client, admin, target = (ns() for _ in range(4))
        inside(switch,"ip","link","add","br0","type","bridge")
        inside(switch,"ip","link","set","br0","up")
        def pair(left,right,left_ns=None,right_ns=None):
            ip("link","add",left,"type","veth","peer","name",right)
            if left_ns: ip("link","set",left,"netns",str(left_ns))
            if right_ns: ip("link","set",right,"netns",str(right_ns))
        pair("ap0","sw_ap",right_ns=switch)
        pair("pi0","sw_pi",left_ns=client,right_ns=switch)
        pair("ctl0","sw_ctl",left_ns=admin,right_ns=switch)
        pair("wan0","target0",right_ns=target)
        for interface in ("sw_ap","sw_pi","sw_ctl"):
            inside(switch,"ip","link","set",interface,"master","br0")
            inside(switch,"ip","link","set",interface,"up")
        def configure(pid,interface,mac,v4,v6):
            def execute(*args):
                return inside(pid,*args) if pid else run(*args)
            execute("ip","link","set","lo","up")
            execute("ip","link","set",interface,"address",mac)
            execute("ip","link","set",interface,"up")
            execute("ip","addr","add",v4,"dev",interface)
            execute("ip","-6","addr","add",v6,"nodad","dev",interface)
        mac, controller = "02:00:00:00:00:20", "02:00:00:00:00:02"
        configure(None,"ap0","02:00:00:00:01:01","10.42.0.1/24","fd42::1/64")
        configure(None,"wan0","02:00:00:00:01:02","192.0.2.1/24","fd43::1/64")
        configure(client,"pi0",mac,"10.42.0.20/24","fd42::20/64")
        configure(admin,"ctl0",controller,"10.42.0.2/24","fd42::2/64")
        configure(target,"target0","02:00:00:00:00:40","192.0.2.2/24","fd43::2/64")
        for pid in (client,admin):
            inside(pid,"ip","route","add","default","via","10.42.0.1")
            inside(pid,"ip","-6","route","add","default","via","fd42::1")
        inside(target,"ip","route","add","10.42.0.0/24","via","192.0.2.1")
        inside(target,"ip","-6","route","add","fd42::/64","via","fd43::1")
        # Fixed IPv6 neighbors keep this firewall test independent of multicast
        # discovery timing in the virtual switch. IPv4 still exercises ARP.
        for pid,interface,address,peer in (
            (client,'pi0','fd42::1','02:00:00:00:01:01'),
            (admin,'ctl0','fd42::1','02:00:00:00:01:01'),
            (target,'target0','fd43::1','02:00:00:00:01:02'),
            (None,'ap0','fd42::20',mac),(None,'ap0','fd42::2',controller),
            (None,'wan0','fd43::2','02:00:00:00:00:40')):
            command=('ip','-6','neigh','replace',address,'lladdr',peer,'nud','permanent','dev',interface)
            inside(pid,*command) if pid else run(*command)
        Path('/tmp/lab-hostapd.conf').write_text('interface=ap0\nctrl_interface=/tmp/hostapd\nmacaddr_acl=0\n')
        stub=Path('/usr/local/bin/hostapd_cli'); stub.write_text(STUB); stub.chmod(0o755)
        Path('/tmp/fake-hostapd.json').write_text(json.dumps({'stations':[mac,controller],'denied':[]}))
        config=LinuxConfig({'ap_interface':'ap0','wan_interface':'wan0','hostapd_config':'/tmp/lab-hostapd.conf',
                            'hostapd_control':'/tmp/hostapd','protected_macs':[controller]})
        devices=[Device(mac,'10.42.0.20','lab client',simulated=False),Device(controller,'10.42.0.2','controller',protected=True,simulated=False)]
        run('nft','add','table','inet','lab_neighbor')
        backend=LinuxEnforcer(config,Path('/tmp/firewall-lab-state'),devices)
        backend.reconcile()
        def ping(pid,address,expected=True):
            result=inside(pid,"ping","-c","1","-W","1",address,check=False)
            if (result.returncode==0) != expected:
                raise AssertionError((address,expected,result.stdout,result.stderr))
        for address in ('192.0.2.2','fd43::2','10.42.0.1'): ping(client,address)
        server_code = """import socket
s=socket.socket()
s.bind(('192.0.2.2',9000))
s.listen()
print('READY',flush=True)
c,_=s.accept()
while True:
    data=c.recv(1)
    if not data: break
    c.sendall(data)
"""
        server = subprocess.Popen(['nsenter','-t',str(target),'-n','python','-u','-c',server_code],stdout=subprocess.PIPE,text=True)
        children.append(server)
        assert server.stdout.readline().strip() == 'READY'
        client_code = """import socket,sys
s=socket.create_connection(('192.0.2.2',9000),timeout=1)
s.settimeout(.5)
print('CONNECTED',flush=True)
for line in sys.stdin:
    try:
        s.sendall(b'x')
        print('ECHO' if s.recv(1)==b'x' else 'CLOSED',flush=True)
    except socket.timeout:
        print('BLOCKED',flush=True)
"""
        tcp = subprocess.Popen(['nsenter','-t',str(client),'-n','python','-u','-c',client_code],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
        children.append(tcp)
        assert tcp.stdout.readline().strip() == 'CONNECTED'
        def probe_tcp(expected):
            tcp.stdin.write('probe\n'); tcp.stdin.flush()
            assert tcp.stdout.readline().strip() == expected
        probe_tcp('ECHO')
        backend.apply('block_wan',mac)
        probe_tcp('BLOCKED')
        tcp.terminate(); server.terminate()
        for address in ('192.0.2.2','fd43::2'): ping(client,address,False)
        for address in ('10.42.0.20','fd42::20'): ping(target,address,False)
        ping(client,'10.42.0.1'); ping(admin,'192.0.2.2')
        backend.apply('quarantine',mac)
        inside(client,'ip','neigh','flush','dev','pi0')
        ping(client,'10.42.0.1',False); ping(client,'fd42::1',False)
        ping(admin,'10.42.0.1')
        backend.apply('restore',mac)
        # Real Wi-Fi reconnection resets neighbor state; the stub leaves veth up.
        inside(client,'ip','neigh','flush','dev','pi0')
        ping(client,'192.0.2.2'); ping(client,'fd43::2'); ping(client,'10.42.0.1')
        backend.apply('quarantine',mac)
        backend.panic()
        ping(client,'192.0.2.2')
        rules=json.loads(run('nft','-j','list','ruleset').stdout)['nftables']
        assert any(item.get('table',{}).get('name')=='lab_neighbor' for item in rules)
        assert not any(item.get('table',{}).get('name')=='securiot_guard' for item in rules)
        print(json.dumps({'real_nftables':True,'ipv4_ipv6_wan_block':True,'return_traffic_blocked':True,'existing_tcp_flow_blocked':True,
            'local_access_survives_wan_block':True,'router_access_blocked_by_quarantine':True,
            'protected_controller_unaffected':True,'restore_and_panic':True,'unrelated_table_preserved':True,
            'hostapd':'stubbed; physical Wi-Fi acceptance still required'},indent=2),flush=True)
    except BaseException:
        print(run('ip','-6','route',check=False).stdout, flush=True)
        for path in Path('/proc/sys/net/ipv6/conf').glob('*/forwarding'):
            print(str(path),path.read_text().strip(),flush=True)
        raise
    finally:
        if backend: backend.close()
        for child in children: child.terminate()
        for child in children: child.wait(timeout=5)

if __name__=='__main__': main()
