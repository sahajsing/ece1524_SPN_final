from p4app import P4Mininet
from mininet.topo import SingleSwitchTopo
from test.baseline_test import run_test

# Create a topo with one CPU and four external ports. Port 1 (h0) is reserved for the CPU.
topo = SingleSwitchTopo(5)
net = P4Mininet(program='simple_router.p4', topo=topo, auto_arp=False)
net.start()

s1 = net.get('s1')

run_test(s1)

# XXX Debugging: print table entries added during the test:
#s1.printTableEntries()
