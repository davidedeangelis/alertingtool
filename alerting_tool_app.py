import bottle, os
from bottle import static_file
from autoscan_app import AutoscanApplication
from bottle import run, route, template, request, error, redirect
from configparser import  ConfigParser


class AlertingToolWebApp(object):
    """
    This is the Alerting Tool Web Application. It exposes the Web Application
    routes, builds the Web Application HTML pages combining the .tpl templates
    within the view directory and the static resources as .js and .css.
    It applies the MVC, Model View Control design pattern.
    """
    def __init__(self, wep_app_url=None, web_app_port=None):
        self._config_reader = ConfigReader()
        if wep_app_url:
            self._host = wep_app_url
        else:
            self._host = self._config_reader.get_web_app_host_port().get('host_name')

        if web_app_port:
            self._port = web_app_port
        else:
            self._port = self._config_reader.get_web_app_host_port().get('host_port')
        self._cwd = os.getcwd()
        self._status = {'status' : True}
        self._autoscan_app = AutoscanApplication(self._config_reader.get_configuration())
        bottle.TEMPLATE_PATH.insert(0, self._cwd + '/views/')#add config file

    def start(self):
        @route('/')
        @route('/alerting/home')
        def alerting_home():
            output = template('alerting_header', data = self._status)
            return output

        @route('/alerting/scans')
        def alerting_scans():
            scans = self._autoscan_app.get_scans_limit(5)
            time_scans_list = []
            for doc in scans:
                time_scans_list.append(str(doc['scan_time']))
            output = template('alerting_scans', time_scans_list = time_scans_list)
            return output

        @route('/alerting/alerts')
        def alerting_alerts():
            alerts = self._autoscan_app.get_alerts_limit(5)
            time_alerts_list = []
            for doc in alerts:
                time_alerts_list.append(str(doc['scan_time']))
            output = template('alerting_alerts', time_alerts_list = time_alerts_list)
            return output

        @route('/alerting/ssls')
        def alerting_ssls():
            alerts = self._autoscan_app.get_ssls_limit(5)
            time_ssls_list = []
            for doc in alerts:
                time_ssls_list.append(str(doc['scan_time']))
            output = template('alerting_ssls', time_ssls_list = time_ssls_list)
            return output

        @route('/alerting/ajax/scans/')
        def alerting_ajax_scans():
            scan_time = request.params.get('data')
            scan_as_html = self._autoscan_app.get_html_scan_result(scan_time)

            return scan_as_html

        @route('/alerting/ajax/alerts/')
        def alerting_ajax_alert():
            scan_time = request.params.get('data')
            alert_as_html = self._autoscan_app.get_html_alert_result(scan_time)
            print("AlertingToolWebApp alerting_ajax_alert:", alert_as_html)
            return alert_as_html

        @route('/alerting/ajax/ssls/')
        def alerting_ajax_ssl():
            scan_time = request.params.get('data')
            ssl_as_html = self._autoscan_app.get_html_ssl_result(scan_time)
            print("AlertingToolWebApp alerting_ajax_ssl:", ssl_as_html)
            return ssl_as_html

        @route('/alerting/home/scan/', method='POST')
        def alerting_scan_do():
            if request.POST.start.strip():
                network = request.POST.network.strip()
                mask = request.POST.mask.strip()
                interval = request.POST.interval
                config = _read_scan_config(request)
                print("AlertingToolWebApp alerting_scan_do: START")
                self._status['status'] = self._autoscan_app.start(config)
            elif request.POST.stop.strip():
                print("AlertingToolWebApp alerting_scan_do: STOP")
                self._status['status'] = self._autoscan_app.stop()
            else:
                pass
            return redirect("/")

        def _read_scan_config(request):

            alerting_config = {
                'email': {
                    'missing_hosts': request.POST.email_missing_hosts,
                    'new_hosts': request.POST.email_new_hosts,
                    'missing_ports': request.POST.email_missing_ports,
                    'new_ports': request.POST.email_new_ports,
                    'vulns': request.POST.email_vulns,
                    'ssl_issues': request.POST.email_ssl,
                },
                'sms': {
                    'missing_hosts': request.POST.sms_missing_hosts,
                    'new_hosts': request.POST.sms_new_hosts,
                    'missing_ports': request.POST.sms_missing_ports,
                    'new_ports': request.POST.sms_new_ports,
                    'vulns': request.POST.sms_vulns,
                    'ssl_issues': request.POST.sms_ssl
                }
            }

            config = {
                'network' : request.POST.network.strip(),
                'mask': request.POST.mask.strip(),
                'schedule_interval': 0,
                'interval': int(request.POST.interval),
                'alerting_config': alerting_config
            }
            return config


        @route('/js/<filename:path>')
        def send_js(filename):
            return static_file(filename, root=str(self._cwd) + '/js/')

        @route('/css/images/<filename:path>')
        def send_js(filename):
            return static_file(filename, root=str(self._cwd) + '/css/images/')

        @route('/css/<filename>.css')
        def send_cs(filename):
            return static_file('{}.css'.format(filename), root=str(self._cwd) + '/css/')

        @error(404)
        @error(403)
        def mistake(code):
            return 'There is something wrong!'
        run(host = self._host, port= self._port, debug = False, reloader = True)

class ConfigReader(object):

    def __init__(self):
        self._config = ConfigParser()

    def _config_section_map(self, section):
        result = {}
        options = self._config.options(section)
        for option in options:
            try:
                result[option] = self._config.get(section, option)
                if result[option] == -1:
                    print("skip: %s" % option)
            except:
                print("exception on %s!" % option)
                result[option] = None
        return result

    def get_configuration(self):
        cwd = os.getcwd()
        config_file = "config/alerting_tool_config.ini"
        self._config.read(os.path.join(cwd, config_file))
        result = {}
        for section in self._config.sections():
            result.update({section: self._config_section_map(section)})
        return result

    def get_web_app_host_port(self):
        alertingtool_config = self.get_configuration().get('alertingtool')
        result = {
            'host_name': alertingtool_config.get('host_name'),
            'host_port': alertingtool_config.get('host_port')
        }
        return result

def main():

    webapp = AlertingToolWebApp('127.0.0.1', 5000)
    webapp.start()

if __name__ == '__main__':
    main()