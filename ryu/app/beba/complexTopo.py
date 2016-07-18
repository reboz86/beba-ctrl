from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.net import Mininet
from mininet.term import makeTerm
from mininet.node import UserSwitch,RemoteController

""" run the topology: sudo -E python ComplexTopo.py """


class ComplexTopo(Topo):
    """Simple topology example."""

    def __init__(self, **opts):
        """Create custom topo."""

        # Initialize topology
        super(ComplexTopo, self).__init__(**opts)

        # Add hosts and switches
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')
        h5 = self.addHost('h5')

        # Adding switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')

        # Add links
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s2)
        self.addLink(h4, s2)
        self.addLink(h5, s1)

        self.addLink(s1, s2)
        self.addLink(s1, s3)
        self.addLink(s2, s3)


def run():
    net = Mininet(topo=ComplexTopo(),switch=UserSwitch,controller=RemoteController,cleanup=True,autoSetMacs=True,listenPort=6634)
    net.start()

    CLI(net)
    net.stop()

# if the script is run directly (sudo custom/optical.py):
if __name__ == '__main__':
    setLogLevel('info')
    run()