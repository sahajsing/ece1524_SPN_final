from p4app import P4Mininet
from mininet.topo import Topo
from control_plane.config import Config
from control_plane.control_plane import Control_plane
from control_plane.tables import Bmv2_grpc_tables_api

class SingleSwitchTopo(Topo):
    def __init__(self, n, **opts):
        Topo.__init__(self, **opts)
        switch = self.addSwitch('s1')
        cpu = self.addHost('cpu', ip='10.10.10.10', mac='08:10:10:10:10:10')
        self.addLink(cpu, switch, port2=1)
        for i in range(1, n+1):
            h = self.addHost('h%d'%i,
                        ip="%d0.%d0.%d0.%d/31"%(i, i, i, i*10+1), mac='%d0:%d0:%d0:%d0:%d0:%d'%(i, i, i, i, i, i*10+1))
            self.addLink(h, switch, port2=i+1)

# Create a topo with one CPU and two hosts. Port 1 (h0) is reserved for the CPU.
topo = SingleSwitchTopo(2)
net = P4Mininet(program='simple_router.p4', topo=topo, auto_arp=False)
net.start()

s1 = net.get('s1')

tables_api = Bmv2_grpc_tables_api(s1)
enable_pwospf = True
config = Config(tables_api, enable_pwospf, s1.intfs[1].name)
config.parse_config_file('./topos/single_router.json')
config.populate_tables()
cp = Control_plane(config)
cp.start()

h1, h2 = net.get('h1'), net.get('h2')

h1.cmd("route add -net 20.20.20.20 netmask 255.255.255.254 gw 10.10.10.10 dev eth0")
h2.cmd("route add -net 10.10.10.10 netmask 255.255.255.254 gw 20.20.20.20 dev eth0")
print(h1.cmd('ping -c1 10.10.10.10')) # ping the router
print(net.ping([h1, h2]))

# Start the mininet CLI to interactively run commands in the network:
#from mininet.cli import CLI
#CLI(net)

cp.join()

# These table entries were added by the CPU:
s1.printTableEntries()
