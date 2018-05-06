from netaddr import *
import os
from platform import system

class Discoverer(object):

    def __init__(self, network, subnet_mask):
        self._network = network
        self._subnet_mask = subnet_mask

    def discover(self):
        """
        Performs the ping sweep of each ip within the network
        addresses range provided.

        :return: a list of hosts up and running
        """
        print('Discoverer discover:')
        ip_range = IPNetwork(self._network)
        ip_range.prefixlen = self._subnet_mask
        hosts = []
        for host in IPNetwork(ip_range):
            if system().lower()=='windows':
                result = 'ping -n 1 -t1 %s >> /dev/null' % host
            else:
                result = 'ping -c 1 -t1 %s >> /dev/null' % host
            print('Discoverer ' + result)
            response = os.system(result)
            if response == 0:
                hosts.append(str(host))
            else:
                pass
        return hosts

    def network(self, network):
        self._network = network

    def mask(self, mask):
        self._subnet_mask = int(mask)