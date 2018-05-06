import vulners, ssl, OpenSSL
from OpenSSL import crypto
from dateutil import parser

class Alerter(object):

    def __init__(self):
        self._vulners_api = vulners.Vulners()

    def inspect_generate_alert_output(self, previous_scan=None, current_scan=None, scan_time=None):
        if previous_scan is None or current_scan is None:
            return None
        else:
            #inspect the network topology for changes
            network_topology = self._inspect_network_topology_changes(previous_scan['hosts_list'], current_scan['hosts_list'])
            current_hosts = network_topology['current_hosts']
            previous_hosts_ports_scan = previous_scan['hosts_ports_scan']
            current_hosts_ports_scan = current_scan['hosts_ports_scan']
            #inspect ports of matching hosts for changes
            if current_hosts:
                if network_topology['new_hosts']:
                    current_hosts.extend(network_topology['new_hosts'])
                ports_services = self._inspect_ports_services_changes(current_hosts, previous_hosts_ports_scan, current_hosts_ports_scan)
            else:
                current_hosts = network_topology['new_hosts']
                ports_services = self._inspect_ports_services_changes(current_hosts, previous_hosts_ports_scan, current_hosts_ports_scan)

            alerting_check = {}
            if len(network_topology.get('missing_hosts')) > 0:
                alerting_check.update({'missing_hosts': True})
            else:
                alerting_check.update({'missing_hosts': False})
            if len(network_topology.get('new_hosts')) > 0:
                alerting_check.update({'new_hosts': True})
            else:
                alerting_check.update({'new_hosts': False})
            for host in ports_services:
                if len(host.get('missing_ports')) > 0:
                    alerting_check.update({'missing_ports': True})
                else:
                    alerting_check.update({'missing_ports': False})
                if len(host.get('new_ports')) > 0:
                    alerting_check.update({'new_ports': True})
                else:
                    alerting_check.update({'new_ports': False})
                if len(host.get('vulnerabilities')) > 0:
                    alerting_check.update({'vulns': True})
                else:
                    alerting_check.update({'vulns': False})
            # SSL ANALYSIS
            ssl_analysis = self._inspect_ssl(current_hosts_ports_scan, scan_time)
            if ssl_analysis.get('alerting_analysis', None):
                alerting_check.update({'ssl_issues': True})
            else:
                alerting_check.update({'ssl_issues': False})

            result = {'scan_time' : scan_time,
                      'network_topology': network_topology,
                      'ports_services': ports_services,
                      'ssl_analysis': ssl_analysis,
                      'alerting_check': alerting_check

            }
            print("Alerter inspect_generate_alert_output: ", result)
            return result

    def _inspect_network_topology_changes(self, previous_scan_hosts, current_scan_hosts):
        # compare the network topology from the previous scan with the current scan.
        previous_scan_s = set(previous_scan_hosts)
        current_scan_s = set(current_scan_hosts)
        result = {'new_hosts' : list(current_scan_s.difference(previous_scan_s)),
                  'missing_hosts' : list(previous_scan_s.difference(current_scan_s)),
                  'current_hosts' : list(current_scan_s.intersection(previous_scan_s))
                  }
        return result

    def _inspect_ports_services_changes(self, current_hosts, previous_hosts_ports_scan, current_hosts_ports_scan):
        result = []
        # inspects each host for open ports and the services running on it.
        for host in current_hosts:
            port_info = {}
            p_proto_ports = set([])
            c_proto_ports = set([])
            for i in previous_hosts_ports_scan:
                if i and len(i) > 0:
                    if host == i[0]['host']:
                        #print(i[0]['protos'][0])
                        for port in i[0]['protos'][0]['proto_ports']:
                            p_proto_ports.add(port['port_number'])
                            #TO DO evaluate to use a comparator for creating a correct dict key and avoid dups
                            port_info.update({port['port_number']: port})
            for i in current_hosts_ports_scan:
                if i and len(i) > 0:
                    if host == i[0]['host']:
                        #i[0]['protos'][0]
                        for port in i[0]['protos'][0]['proto_ports']:
                            c_proto_ports.add(port['port_number'])
                            port_info.update({port['port_number']: port})
            #CREATE port scan and vuln analysis result
            new_ports = c_proto_ports.difference(p_proto_ports)
            missing_ports = p_proto_ports.difference(c_proto_ports)
            current_ports = c_proto_ports.intersection(p_proto_ports)
            uninion_ports = new_ports.union(current_ports)
            print("Alerter _inspect_ports_services_changes port_info: ", port_info)
            print("Alerter _inspect_ports_services_changes uninion_ports: ", uninion_ports)
            vulnerabilities = self._generate_vuln_analysis(port_info, uninion_ports)
            print("Alerter _inspect_ports_services_changes vulnerabilities: ", vulnerabilities)
            result.append({ 'host': host,
                            'new_ports' : list(new_ports),
                            'missing_ports' : list(missing_ports),
                            'current_ports' : list(current_ports),
                            'vulnerabilities': vulnerabilities
                           })
        return result

    def trim_vuln(self, vulnerabilities_list, port_key):
        result = []
        if vulnerabilities_list:
            for vuln_list in vulnerabilities_list:
                for vuln in vuln_list:
                    white_vuln = {}
                    print('Alerter _generate_vuln_analysis trim_vuln: ', vuln)
                    white_vuln.update({'port': port_key})
                    id = vuln.get('id', 'No ID found')
                    white_vuln.update({'id': id})
                    description = vuln.get('description', 'No description found')
                    description = description[:150]
                    description += "..."
                    white_vuln.update({'description': description})
                    href = vuln.get('href', 'No ID href')
                    white_vuln.update({'href': href})
                    result.append(white_vuln)
        return result

    def trim_expl(self, exploit_list, port_key):
        result = []
        if exploit_list:
            print('Alerter _generate_vuln_analysis trim_expl exploit_list: ', exploit_list)
            for expl in exploit_list:
                white_expl = {}
                print('Alerter _generate_vuln_analysis trim_expl: ', expl)
                white_expl.update({'port': port_key})
                id = expl.get('id', 'No ID found')
                white_expl.update({'id': id})
                title = expl.get('title', 'No title found')
                white_expl.update({'title': title})
                href = expl.get('href', 'No ID href')
                white_expl.update({'href': href})
                result.append(white_expl)
        return result

    def _generate_vuln_analysis(self, port_info, ports):

        def get_vuln_by_cpe(vulners_api, cpe, port_key):
            print("get_vuln_by_cpe(vulners_api, %s, %s)" % (cpe, port_key))
            result = {}
            try:
                cpe_results = vulners_api.cpeVulnerabilities(cpe, maxVulnerabilities=20)
                exploit_list = cpe_results.get('exploit')
                vulnerabilities_list = [cpe_results.get(key) for key in cpe_results if key not in ['info', 'blog', 'bugbounty']]
                trim_vulns = self.trim_vuln(vulnerabilities_list, port_key)
                trim_expl = self.trim_expl(exploit_list, port_key)
                if trim_expl:
                    result.update({"exploit_list" : trim_expl})
                if trim_vulns:
                    result.update({"vulnerabilities_list" : trim_vulns})
            except TypeError as te:
                print("Alerter _generate_vuln_analysis get_vuln_by_cpe Type Error occured: {0}".format(te))
            except ValueError as ve:
                print("Alerter _generate_vuln_analysis get_vuln_by_cpe Value Error occured: {0}".format(ve))
            finally:
                return result

        def get_vuln_by_name_and_version(vulners_api, name, version, port_key):
            print("get_vuln_by_name_and_version(vulners_api, %s, %s, %s)" % (name, version, port_key))
            result = {}
            try:
                results = vulners_api.softwareVulnerabilities(name, version, maxVulnerabilities=20)
                exploit_list = results.get('exploit')
                vulnerabilities_list = [results.get(key) for key in results if key not in ['info', 'blog', 'bugbounty']]
                trim_vulns = self.trim_vuln(vulnerabilities_list, port_key)
                trim_expl = self.trim_expl(exploit_list, port_key)
                if trim_expl:
                    result.update({"exploit_list" : trim_expl})
                if trim_vulns:
                    result.update({"vulnerabilities_list" : trim_vulns})
            except TypeError as te:
                print("Alerter _generate_vuln_analysis get_vuln_by_name_and_version Type Error occured: {0}".format(te))
            except ValueError as ve:
                print("Alerter _generate_vuln_analysis get_vuln_by_name_and_version Value Error occured: {0}".format(ve))
            finally:
                return result

        def get_vuln_by_product_and_version(vulners_api, product, version, port_key):
            print("get_vuln_by_product_and_version(vulners_api, %s, %s, %s)" % (product, version, port_key))
            result = {}
            try:
                if version:
                    product_version = product + ' ' + version
                else:
                    product_version = product
                exploit_list = vulners_api.searchExploit(product_version, limit=20)
                trim_expl = self.trim_expl(exploit_list, port_key)
                if trim_expl:
                    result.update({"exploit_list" : trim_expl})
            except TypeError as te:
                print("Alerter _generate_vuln_analysis get_vuln_by_product_and_version Type Error occured: {0}".format(te))
            except ValueError as ve:
                print("Alerter _generate_vuln_analysis get_vuln_by_product_and_version Value Error occured: {0}".format(ve))
            finally:
                return result
        result = {
            "vulnerabilities_list": [],
            "exploit_list": []
        }
        for port_key in ports:
            port_nalysis = port_info.get(port_key)

            if port_nalysis["port_name"]:
                na_ve = get_vuln_by_name_and_version(self._vulners_api, port_nalysis["port_name"], port_nalysis["port_version"], port_key)
                if na_ve.get("exploit_list"):
                    result.get("exploit_list").extend(na_ve.get("exploit_list"))
                if na_ve.get("vulnerabilities_list"):
                    result.get("vulnerabilities_list").extend(na_ve.get("vulnerabilities_list"))
            if port_nalysis["port_product"]:
                pr_ve = get_vuln_by_product_and_version(self._vulners_api, port_nalysis["port_product"], port_nalysis["port_version"], port_key)
                if pr_ve.get("exploit_list"):
                    result.get("exploit_list").extend(pr_ve.get("exploit_list"))
                if pr_ve.get("vulnerabilities_list"):
                    result.get("vulnerabilities_list").extend(pr_ve.get("vulnerabilities_list"))
            if port_nalysis["port_cpe"]:
                cpe = get_vuln_by_cpe(self._vulners_api, port_nalysis["port_cpe"], port_key)
                if cpe.get("exploit_list"):
                    result.get("exploit_list").extend(cpe.get("exploit_list"))
                if cpe.get("vulnerabilities_list"):
                    result.get("vulnerabilities_list").extend(cpe.get("vulnerabilities_list"))
        return result

    def _inspect_ssl(self, host_list, scan_time):
        """
        Inspects the SSL certificates for the defined set of anomalies.

        :param host_list:
        :param scan_time:
        :return:
        """
        result = {
            'scan_time': scan_time,
            'analysis': [],
            'alerting_analysis': False
        }

        def _cert_has_issues(cert, host_name):
            result = {}
            if cert.has_expired():  # check if the certificate is expired
                result.update({
                    'has_expired': True
                })
            if cert.get_pubkey().bits() < 2048:  # check if the certificate has a pub key with minimum 2048 bits
                result.update({
                    'pub_key_length_lt_2048': cert.get_pubkey().bits()
                })
            components = dict((x.decode("utf-8"), y.decode("utf-8")) for x, y in cert.get_subject().get_components())
            common_name = components.get("CN")
            if host_name and common_name != host_name:  # check if the certificate is common name is equal to hostname
                result.update({
                    'common_name': common_name,
                    'host_name': host_name
                })
            if cert.get_signature_algorithm().decode("utf-8") != "sha256WithRSAEncryption":
                # check if the certificate uses a safe sign algorithm, minimum sha256
                result.update({
                    'unsafe_sign_algorithm': cert.get_signature_algorithm().decode("utf-8")
                })
            return result

        def _decode_pub_key(type):
            if type == OpenSSL.crypto.TYPE_DSA:
                return "DSA"
            elif type ==OpenSSL.crypto.TYPE_RSA:
                return "RSA"
            else:
                return type

        def _analyse_ssl_certificate(ip, host_name, port, host_port_name, port_product):
            result = None
            try:
                print("_analyse_ssl_certificate ip %s, host name %s, port %s " % (ip, host_name, port))
                cert = ssl.get_server_certificate((ip, port))
                cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
                cert_issues = _cert_has_issues(cert, host_name)
                cert.get_signature_algorithm().__hash__()
                port_name = None
                if host_port_name:
                    port_name = host_port_name[0]
                product = None
                if port_product:
                    product = port_product[0]
                result = {
                    'host_ip': ip,
                    'host_name': host_name,
                    'port': port,
                    'host_port_name': port_name,
                    'port_product': product,
                    'has_expired' : cert.has_expired(),
                    'starts_being_valid' : parser.parse(cert.get_notBefore()),
                    'stops being valid' : parser.parse(cert.get_notAfter()),
                    'serial_number' : str(cert.get_serial_number()),
                    'signature_algorithm' : cert.get_signature_algorithm().decode("utf-8") ,
                    'pub_key': _decode_pub_key(cert.get_pubkey().type()),
                    'pub_key_bits': cert.get_pubkey().bits(),
                    'subject' : {
                        'components': dict((x.decode("utf-8"), y.decode("utf-8")) for x, y in cert.get_subject().get_components())
                    },
                    'issuer' : dict((x.decode("utf-8"), y.decode("utf-8")) for x, y in cert.get_issuer().get_components()),
                    'cert_issues': cert_issues
                }
            except Exception as e:
                print("Alerter inspect_ssl: ", e)
            finally:
                return result
            return result

        for host in host_list:
            if host and len(host) > 0:
                host_ip = host[0].get('host')
                host_name = host[0].get('host_name')
                for port in host[0].get('protos')[0].get('proto_ports'):
                    host_port = port.get('port_number')
                    if host_port == 443:
                        host_port_name = port.get('port_name'),
                        port_product = port.get('port_product'),
                        analysis = _analyse_ssl_certificate(host_ip, host_name, host_port, host_port_name, port_product)
                        if analysis:
                            result['analysis'].append(analysis)
                            if analysis.get('cert_issues', None):
                                result.update({'alerting_analysis': analysis.get('cert_issues')})
        return result