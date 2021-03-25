from p4app import P4Mininet
from mininet.topo import Topo
from control_plane.config import Config
from control_plane.control_plane import Control_plane
from control_plane.tables import Bmv2_grpc_tables_api
from control_plane.utils.consts import *

class TriangleTopo(Topo):
    def __init__(self, **opts):
        Topo.__init__(self, **opts)
        cpus = [self.addHost('cpu%d'%i, ip="10.0.0.%d"%i, mac='00:00:00:00:11:0%d'%i) for i in range(1, 4)]
        switches = [self.addSwitch('s%d'%i) for i in range(1, 4)]
        s1, s2, s3 = switches
        h1 = self.addHost('h1', ip="10.0.1.3/31", mac='00:00:00:00:01:03')
        h2 = self.addHost('h2', ip="10.0.1.11/31", mac='00:00:00:00:01:11')
        h3 = self.addHost('h3', ip="10.0.1.13/31", mac='00:00:00:00:01:13')
        hosts = [h1, h2, h3]
        for i in range(3): self.addLink(cpus[i], switches[i], port2=1)
        for i in range(3): self.addLink(hosts[i], switches[i], port2=2)
        self.addLink(s1, s2, port1=3, port2=3)
        self.addLink(s1, s3, port1=4, port2=3)
        self.addLink(s2, s3, port1=4, port2=4)

topo = TriangleTopo()
net = P4Mininet(program='simple_router.p4', topo=topo, auto_arp=False)
net.start()

s1, s2, s3 = net.get('s1', 's2', 's3')

cpus = []
for i in range(1, 4):
    sw = net.get('s%d'%i)
    tables_api = Bmv2_grpc_tables_api(sw)
    enable_pwospf = True
    config = Config(tables_api, enable_pwospf, sw.intfs[1].name)
    config.parse_config_file('./topos/triangle/s%d.json'%i)
    config.populate_tables()
    cp = Control_plane(config)
    cp.start()
    cpus.append(cp)

h1, h2, h3 = net.get('h1', 'h2', 'h3')

time.sleep(LSUINT + 1) # wait for PWOSPF to run

h1.cmd("route add -net 10.0.1.0 netmask 255.255.255.0 gw 10.0.1.2 dev eth0")
h2.cmd("route add -net 10.0.1.0 netmask 255.255.255.0 gw 10.0.1.10 dev eth0")
h3.cmd("route add -net 10.0.1.0 netmask 255.255.255.0 gw 10.0.1.12 dev eth0")
print(h1.cmd('ping -c1 10.0.1.2')) # ping the router
print(net.ping([h1, h2, h3]))

for cp in cpus: cp.join()

# These table entries were added by the CPU:
s1.printTableEntries()
