import nmap

class Nmapper(object):

    def __init__(self, port_range=None):
        if port_range is not None:
            self._port_range = port_range
        else:
            self._port_range = '0-1000'

    def scan_ports_per_host(self, host_ip):
        """
        The Nmapper uses the nmap library for interacting with the
        underlying nmap application installed on the Application Server

        :param host_ip:
        :return: nmap scan result
        """
        nm = nmap.PortScanner()
        print("I'm scanning host ports: " + host_ip)
        nm.scan(host_ip)
        result = self._extract_info(nm)
        return result

    def _extract_info(self, nm):
        result = []
        for host in nm.all_hosts():
            e_protos = []
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                e_ports = []
                for port in lport:
                    e_port = {'port_number' : port,
                              'port_state' : nm[host][proto][port]['state'],
                              'port_reason' : nm[host][proto][port]['reason'],
                              'port_name' : nm[host][proto][port]['name'],
                              'port_product' : nm[host][proto][port]['product'],
                              'port_extrainfo' : nm[host][proto][port]['extrainfo'],
                              'port_reason' : nm[host][proto][port]['reason'],
                              'port_version' : nm[host][proto][port]['version'],
                              'port_conf' : nm[host][proto][port]['conf'],
                              'port_cpe' : nm[host][proto][port]['cpe']
                              }
                    e_ports.append(e_port)
                e_proto = {'proto_name' : proto, 'proto_ports' : e_ports}
                e_protos.append(e_proto)
            host = {'host': host, 'host_name': nm[host].hostname(), 'host_state': nm[host].state(), 'protos': e_protos}
            result.append(host)
        return result