import time
from mininet.topo import Topo
from mininet.cli import CLI
from mininet.net import Mininet
from mininet.link import TCLink


class BasicTopo( Topo ):
    """
       host--switch---host
                |
              host
    """
    def __init__( self ):
        # Initialize topology
        Topo.__init__( self )

        # Set easy to remember mac addresses
        host1 = self.addHost( 'h1', ip="10.0.0.1", mac="00:00:00:00:00:01" )
        host2 = self.addHost( 'h2', ip="10.0.0.2", mac="00:00:00:00:00:02" )
        host3 = self.addHost( 'h3', ip="10.0.0.3", mac="00:00:00:00:00:03" )
        switch = self.addSwitch( 's1' )

        # The http server
        self.addLink(host1, switch)
        # The legitimate client
        # Delay simulates the fact that h3 can get their packets in before h2
        self.addLink(host2, switch, delay='20ms')
        # The attacker trying to desynchronise the connection
        self.addLink(host3, switch)


# Print all seen traffic from a host to a file
# You can view this file with "wireshark filename"
def start_tcpdump(host):
    print("Starting tcpdump on host %s interface %s" % (host, host.defaultIntf()))
    host.cmd("tcpdump -vv -i %s -w %sdump.pcap &" % (host.defaultIntf(), host))


def stop_telnet(host):
    print("Stopping telnet")
    host.cmd('sudo /etc/init.d/xinetd stop')


def start_telnet(host):
    stop_telnet(host)
    print("Starting telnet on host %s..." % host)
    host.cmd('sudo /etc/init.d/xinetd start')
    print("Telnet started, use 'telnet %s' to connect" % host.IP())


def start_attacker(host):
    print("Starting attacker script on %s" % host)
    host.cmd("sudo python attack.py &")


def start_tcp_server(host):
    print("Starting a TCP server on host %s..." % host)
    # Run an http server in the background
    host.cmd("python -m SimpleHTTPServer 80 &")
    # make sure the server is up ad running before we return
    time.sleep(2)
    print("TCP server now running")


def perform_get(host):
    print("Attempting to get info from http server..")
    result = host.cmd("wget -O - '10.0.0.1'")
    print(result)


def main():
    topo = BasicTopo()
    net = Mininet(topo=topo, link=TCLink)
    # Mininet.staticArp(net)
    net.start()
    h1, h2, h3, s1 = net.get('h1', 'h2', 'h3', 's1')
    # start_tcp_server(h1)
    # perform_get(h2)
    start_tcpdump(h3)
    # start_attacker(h3)
    start_telnet(h1)
    # Make sure all messages are received by h3
    s1.cmd("ovs-ofctl add-flow s1 in_port=1,actions=flood")
    s1.cmd("ovs-ofctl add-flow s1 in_port=2,actions=flood")
    # Open cli in case we want to do additional debugging
    CLI(net)
    stop_telnet(h1)
    net.stop()

if __name__ == "__main__":
    main()
