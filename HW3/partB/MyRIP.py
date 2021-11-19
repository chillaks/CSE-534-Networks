import time
from mininet.topo import Topo
from mininet.node import Node
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.log import setLogLevel, info


#                                           TOPOLOGY
#
#                                    (r2-eth0)    (r2-eth1)
#                    (r1-eth1)     10.1.2.1/24 | 10.1.4.1/24     (r4-eth1)
#                  10.1.2.2/24 +---------------R2---------------+ 10.1.4.2/24
#                             /                                  \
#  10.1.1.2/24 | 10.1.1.1/24 /                                    \ 10.1.6.1/24 | 10.1.6.2/24
#       H1------------------R1                                    R4------------------H2
#    (h1-eth0)     (r1-eth0) \                                    / (r4-eth0)      (h2-eth0)
#                             \                                  /
#                  10.1.3.2/24 +---------------R3---------------+ 10.1.5.2/24
#                   (r1-eth2)      10.1.3.1/24 | 10.1.5.1/24        (r4-eth2)
#                                    (r3-eth0)    (r3-eth1)

# IP Addresses for all router interfaces, as seen in the topology diagram above
r1_eth0_ip = '10.1.1.1'
r1_eth1_ip = '10.1.2.2'
r1_eth2_ip = '10.1.3.2'
r2_eth0_ip = '10.1.2.1'
r2_eth1_ip = '10.1.4.1'
r3_eth0_ip = '10.1.3.1'
r3_eth1_ip = '10.1.5.1'
r4_eth0_ip = '10.1.6.1'
r4_eth1_ip = '10.1.4.2'
r4_eth2_ip = '10.1.5.2'
# IP Addresses for all hosts, as seen in the topology diagram above
h1_eth0_ip = '10.1.1.2'
h2_eth0_ip = '10.1.6.2'

# Router Interface Names
r1_eth0 = 'r1-eth0'
r1_eth1 = 'r1-eth1'
r1_eth2 = 'r1-eth2'
r2_eth0 = 'r2-eth0'
r2_eth1 = 'r2-eth1'
r3_eth0 = 'r3-eth0'
r3_eth1 = 'r3-eth1'
r4_eth0 = 'r4-eth0'
r4_eth1 = 'r4-eth1'
r4_eth2 = 'r4-eth2'
h1_eth0 = 'h1-eth0'
h2_eth0 = 'h2-eth0'

R1 = 'R1'
R2 = 'R2'
R3 = 'R3'
R4 = 'R4'
H1 = 'H1'
H2 = 'H2'

# A Node with IP forwarding enabled and the BIRD routing daemon running
class Router(Node): 
    def config(self, **params):
        super(Router, self).config(**params)
        self.cmd('sysctl net.ipv4.ip_forward=1')
        # Start the Bird Daemon on all the routers
        self.cmd('cd %s' % self.name)
        self.cmd('bird -l')

    def terminate(self):
        self.cmd('sysctl net.ipv4.ip_forward=0')
        # Terminate bird process before shutting down
        self.cmd('birdc -l down')
        super(Router, self).terminate()

def getIP(ip: str, subnet_mask: int, get_subnet_addr: bool = False):
    if get_subnet_addr:
        ip = ip.split('.')
        ip[3] = '0'
        return '{}/{}'.format('.'.join(ip), subnet_mask)
    return '{}/{}'.format(ip, subnet_mask)

class MyTopo(Topo):
    def build(self, **_opts):
        # Create LinuxRouter objects which have IP forwarding set by default
        r1 = self.addHost(R1, cls = Router, ip = getIP(r1_eth0_ip, 24))
        r2 = self.addHost(R2, cls = Router, ip = getIP(r2_eth0_ip, 24))
        r3 = self.addHost(R3, cls = Router, ip = getIP(r3_eth0_ip, 24))
        r4 = self.addHost(R4, cls = Router, ip = getIP(r4_eth0_ip, 24))

        # Create hosts
        h1 = self.addHost(name = H1, ip = getIP(h1_eth0_ip, 24), defaultRoute = 'via {}'.format(r1_eth0_ip))
        h2 = self.addHost(name = H2, ip = getIP(h2_eth0_ip, 24), defaultRoute = 'via {}'.format(r4_eth0_ip))

        # Link both hosts to edge routers
        self.addLink(h1, r1, intfName1 = h1_eth0, intfName2 = r1_eth0,
            params1 = {'ip': getIP(h1_eth0_ip, 24)}, params2 = {'ip': getIP(r1_eth0_ip, 24)})
        self.addLink(h2, r4, intfName1 = h2_eth0, intfName2 = r4_eth0,
            params1 = {'ip': getIP(h2_eth0_ip, 24)}, params2 = {'ip': getIP(r4_eth0_ip, 24)})

        # Link all routers
        self.addLink(r1, r2, intfName1 = r1_eth1, intfName2 = r2_eth0,
            params1 = {'ip': getIP(r1_eth1_ip, 24)}, params2 = {'ip': getIP(r2_eth0_ip, 24)})
        self.addLink(r1, r3, intfName1 = r1_eth2, intfName2 = r3_eth0,
            params1 = {'ip': getIP(r1_eth2_ip, 24)}, params2 = {'ip': getIP(r3_eth0_ip, 24)})
        self.addLink(r2, r4, intfName1 = r2_eth1, intfName2 = r4_eth1,
            params1 = {'ip': getIP(r2_eth1_ip, 24)}, params2 = {'ip': getIP(r4_eth1_ip, 24)})
        self.addLink(r3, r4, intfName1 = r3_eth1, intfName2 = r4_eth2,
            params1 = {'ip': getIP(r3_eth1_ip, 24)}, params2 = {'ip': getIP(r4_eth2_ip, 24)})

def run():
    topo = MyTopo()
    net = Mininet(topo = topo)
    net.start()

    # Display the routing tables
    for router in [R1, R2, R3, R4]:
        info('\nRouting Table on Router {}:\n'.format(router))
        info(net[router].cmd('route'))

    # Add some delay to allow each router to broadcast its IPs to the other routers
    time.sleep(1)
    # Pingall result
    info('\nPinging all nodes and routers\n')
    info(net.pingAll())

    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel( 'info' )
    run()