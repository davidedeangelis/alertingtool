import schedule, datetime, time, functools, threading, smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from discoverer import Discoverer
from mdb_client import MongoDBClient
from nmapper import Nmapper
from alerter import Alerter
from json import dumps
from json2html import *
from dateutil import parser
from twilio.rest import Client

class AutoscanApplication(object):
    """
    This is the Alerting Tool Business logic class. It applies the
    main buisiness logic for generating the scans, the alerts and
    the notifications. It orchestrates the interaction between each
    componenets of the application.
    """
    def __init__(self, config=None):
        self.config_mdb_atlas = config.get('mdb_atlas')
        self.config_email = config.get('email')
        self.config_sms = config.get('sms')
        self._discoverer = Discoverer(None, None)
        self._nmapper = Nmapper()
        self._alerter = Alerter()
        self._scan_db = MongoDBClient(self.config_mdb_atlas.get('scan_cluster_name'), self.config_mdb_atlas.get('scan_username'), self.config_mdb_atlas.get('scan_password'), self.config_mdb_atlas.get('scan_db'))
        self._running_event = None
        self._previous_scan = {'hosts_list': [], 'hosts_ports_scan': []}
        self._email_client = EmailClient(self.config_email.get('email_from_addr'), self.config_email.get('email_password'), self.config_email.get('email_smtp_server'), self.config_email.get('email_smtp_server_port'))
        self._sms_client = SmsClient(self.config_sms.get('sms_account_sid'), self.config_sms.get('sms_auth_token'))

    def catch_exceptions(cancel_on_failure=False):
        def catch_exceptions_decorator(job_func):
            @functools.wraps(job_func)
            def wrapper(*args, **kwargs):
                try:
                    return job_func(*args, **kwargs)
                except:
                    ('Exception caught: ')
                    import traceback
                    print(traceback.format_exc())
                    if cancel_on_failure:
                        return schedule.CancelJob
            return wrapper
        return catch_exceptions_decorator

    @catch_exceptions(cancel_on_failure=False)
    def _job(self):
        """
        The job represents each steps executed every time the scheduler
        is triggered.
        :return:
        """
        print("AutoscanApplication _job Discovering hosts: ")
        scan_result = self._create_scan_result()
        print("AutoscanApplication _job Saving the scan: ")
        self._save_scan_result(scan_result)
        print("AutoscanApplication _job Scan saved: ")
        alerts_result = {}
        alerts_result = self._alerter.inspect_generate_alert_output(self._previous_scan, scan_result, scan_result['scan_time'])
        print("AutoscanApplication _job Saving the alerts: ")
        ssls_result = alerts_result.get('ssl_analysis', None)
        alerts_result.pop('ssl_analysis')
        alerting_check = alerts_result.get('alerting_check', None)
        alerts_result.pop('alerting_check')
        self._save_alerts_result(alerts_result)
        print("AutoscanApplication _job Alerts saved: ")
        print("AutoscanApplication _job Saving the ssls: ")
        self._save_ssls_result(ssls_result)
        print("AutoscanApplication _job SSLs saved: ")
        self._previous_scan = scan_result
        self._verify_and_generate_alerts(self._alerting_config, alerting_check, scan_result['scan_time'])

    def _run_continuously(self, schedule, interval):
        """Continuously run, while executing pending jobs at each elapsed
        time interval.
        """
        cease_continuous_run = threading.Event()

        class ScheduleThread(threading.Thread):
            @classmethod
            def run(cls):
                print('ScheduleThread run:')
                while not cease_continuous_run.is_set():
                    print('ScheduleThread schedule: ' + str(cease_continuous_run.is_set()))
                    print('ScheduleThread schedule run_pending:')
                    schedule.run_pending()
                    time.sleep(interval)

        continuous_thread = ScheduleThread()
        continuous_thread.start()
        return cease_continuous_run

    def _print_scans(self):
        discoveries = self._scan_db.collection(self.config_mdb_atlas.get('scans_coll'))
        cursor = discoveries.find()
        for document in cursor:
            print(document)

    def start(self, config):
        """
        Creates the job to be scheduled and returns the control to
        the main thread the Web Application

        :param config:
        :return:
        """
        print('AutoscanApplication start:')
        if config['network'] != None:
            self._discoverer.network(config['network'])
        if config['mask'] != None:
            self._discoverer.mask(config['mask'])
        schedule.every(config['schedule_interval']).minutes.do(self._job).tag('scan')
        self._running_event = self._run_continuously(schedule, config['interval'])
        p_scan = self._find_last_scan()
        if p_scan.count():
            self._previous_scan = p_scan[0]
        self._alerting_config = config['alerting_config']
        return self._running_event.is_set()

    def stop(self):
        """
        Stop the scheduler for executing the next job. The current job can't
        be stopped if it is still running.
        :return:
        """
        print('AutoscanApplication stop:')
        result = True
        if self._running_event is not None:
            self._running_event.set()
            schedule.clear('scan')
            result = self._running_event.is_set()
        return result

    def _verify_and_generate_alerts(self, alerting_config, alerting_check, scan_time):
        """
        Compares the current alerting configuration and the alerts checks executed by
        the Alerter class

        :param alerting_config:
        :param alerting_check:
        :param scan_time:
        :return:
        """
        def _verify_email(email_ac, alerting_check):
            result = False
            if email_ac.get('missing_hosts', False) and alerting_check.get('missing_hosts'):
                result = True
            elif email_ac.get('new_hosts', False) and alerting_check.get('new_hosts'):
                result = True
            elif email_ac.get('missing_ports', False) and alerting_check.get('missing_ports'):
                result = True
            elif email_ac.get('new_ports', False) and alerting_check.get('new_ports'):
                result = True
            elif email_ac.get('vulns', False) and alerting_check.get('vulns'):
                result = True
            elif email_ac.get('ssl_issues', False) and alerting_check.get('ssl_issues'):
                result = True
            return result

        def _verify_sms(sms_ac, alerting_check):
            result = False
            if sms_ac.get('missing_hosts', False) and alerting_check.get('missing_hosts'):
                result = True
            elif sms_ac.get('new_hosts', False) and alerting_check.get('new_hosts'):
                result = True
            elif sms_ac.get('missing_ports', False) and alerting_check.get('missing_ports'):
                result = True
            elif sms_ac.get('new_ports', False) and alerting_check.get('new_ports'):
                result = True
            elif sms_ac.get('vulns', False) and alerting_check.get('vulns'):
                result = True
            elif sms_ac.get('ssl_issues', False) and alerting_check.get('ssl_issues'):
                result = True
            return result
        print("AutoscanApplication _verify_and_generate_alerts alerting_config: ", alerting_config)
        print("AutoscanApplication _verify_and_generate_alerts alerting_check: ", alerting_check)
        print("AutoscanApplication _job Checking for Sending Email: ")
        if _verify_email(email_ac=alerting_config.get('email'), alerting_check=alerting_check):
            self._create_and_send_email(scan_time)
            print("AutoscanApplication _job Email Sent: ")
        else:
            print("AutoscanApplication _job Email NOT Sent: ")
        print("AutoscanApplication _job Checking for Sending SMS: ")
        if _verify_sms(sms_ac=alerting_config.get('sms'), alerting_check=alerting_check):
            self._create_and_send_sms(scan_time)
            print("AutoscanApplication _job SMS Sent: ")
        else:
            print("AutoscanApplication _job SMS NOT Sent: ")

    def _create_and_send_sms(self, scan_time):
        """
        Generates a simple SMS body message and sends it to the SMS external subsystem.

        :param scan_time:
        :return:
        """
        body = "Alerting Tool: new alerts for network topology, vulnerabilities " \
               "or SSL certificates, please verify ASAP. Scan Time: " + str(scan_time)
        self._sms_client.send_sms_alert(self.config_sms.get('sms_to_number'), self.config_sms.get('sms_from_number'), body)

    def _create_and_send_email(self, scan_time):
        """
        Generates the HTML body and sends it to the SMTP external subsystem.

        :param scan_time:
        :return:
        """
        text_part = "AlertingTool Email Report from scan finished on: " + str(scan_time)
        subject = "AlertingTool Email Report " + str(scan_time)
        toaddr_list = [e.strip() for e in self.config_email.get('email_to_addr').split(',')]
        html_part = "<h1>Network Topology and Vulnerabilities Alert</h1> <br> " + self.get_html_alert_result(str(scan_time)) + "<h1>SSL Analysis Alert</h1> <br> " + self.get_html_ssl_result(str(scan_time))
        self._email_client.send_mail_alert(toaddr_list, text_part, html_part, subject)

    def get_html_scan_result(self, scan_time):
        input = self._get_scan_by_date(self._parse_string_to_datetime(scan_time))
        converted = json2html.convert(json = input, table_attributes="id=\"scan-table\"")
        return converted

    def get_html_alert_result(self, scan_time):
        input = self._get_alert_by_date(self._parse_string_to_datetime(scan_time))
        converted = json2html.convert(json = input, table_attributes="id=\"alerts-table\"")
        return converted

    def get_html_ssl_result(self, scan_time):
        input = self._get_ssl_by_date(self._parse_string_to_datetime(scan_time))
        converted = json2html.convert(json = input, table_attributes="id=\"ssls-table\"")
        return converted

    def get_scans_limit(self, limit):
        return self._get_last_scans_limit(limit)

    def get_alerts_limit(self, limit):
        return self._get_last_alerts_limit(limit)

    def get_ssls_limit(self, limit):
        return self._get_last_ssls_limit(limit)

    def _parse_string_to_datetime(self, string_time):
        return parser.parse(string_time)

    def _get_scan_by_date(self, scantime):
        result = self._scan_db.collection(self.config_mdb_atlas.get('scans_coll')).find_one({"scan_time" : scantime}, {'_id': 0})
        return result

    def _get_alert_by_date(self, scantime):
        result = self._scan_db.collection(self.config_mdb_atlas.get('alerts_coll')).find_one({"scan_time" : scantime}, {'_id': 0})
        return result

    def _get_ssl_by_date(self, scantime):
        result = self._scan_db.collection(self.config_mdb_atlas.get('ssls_coll')).find_one({"scan_time" : scantime}, {'_id': 0})
        return result

    def _save_scan_result(self, scan_result):
        discoveries = self._scan_db.collection(self.config_mdb_atlas.get('scans_coll'))
        discoveries.insert_one(scan_result)

    def _save_alerts_result(self, alerts_result):
        alerts = self._scan_db.collection(self.config_mdb_atlas.get('alerts_coll'))
        alerts.insert_one(alerts_result)

    def _save_ssls_result(self, ssls_result):
        if ssls_result:
            ssls = self._scan_db.collection(self.config_mdb_atlas.get('ssls_coll'))
            ssls.insert_one(ssls_result)

    def _get_last_scans_limit(self, limit=1):
        print("autoscan_app _get_last_scans_limit")
        return self._scan_db.collection(self.config_mdb_atlas.get('scans_coll')).find().sort("scan_time" , -1).limit(limit)

    def _get_last_alerts_limit(self, limit=1):
        print("autoscan_app _get_last_alert_limit")
        return self._scan_db.collection(self.config_mdb_atlas.get('alerts_coll')).find().sort("scan_time" , -1).limit(limit)

    def _get_last_ssls_limit(self, limit=1):
        print("autoscan_app _get_last_ssls_limit")
        return self._scan_db.collection(self.config_mdb_atlas.get('ssls_coll')).find().sort("scan_time" , -1).limit(limit)

    def _find_last_scan(self):
        print('AutoscanApplication _find_last_scan:')
        return self._scan_db.collection(self.config_mdb_atlas.get('scans_coll')).find().sort("scan_time" , -1).limit(1)

    def get_alert(self, scan_time=None):
        if not scan_time:
            return self._find_last_alert()

    def _find_last_alert(self):
        print('AutoscanApplication _find_last_alert')
        alerts = self._scan_db.collection(self.config_mdb_atlas.get('alerts_coll')).find({}, {'_id': False, 'scan_time' : False}).sort("scan_time" , -1).limit(1)
        result = {"message" : "no alerts"}
        if alerts.count():
            result = alerts[0]
            print(result)
        return dumps(result)

    def _create_scan_result(self):
        print('AutoscanApplication _create_scan_result:')
        ip_discovery = self._discoverer.discover()
        nmapper_result = []
        for ip in ip_discovery:
            scan_result = self._nmapper.scan_ports_per_host(ip)
            nmapper_result.append(scan_result)

        result = {
                'scan_time': datetime.datetime.utcnow(),
                'hosts_list': ip_discovery,
                'hosts_ports_scan': nmapper_result
        }

        return result

class EmailClient(object):
    """
    Email Client for interacting with the SMTP external subsustem.
    """

    def __init__(self, fromaddr, password, smtp_server, smtp_server_port):
        self._fromaddr = fromaddr
        self._password = password
        self._smtp_server = smtp_server
        self._smtp_server_port = smtp_server_port

    def send_mail_alert(self, toaddr_list, text_part, html_part, subject):
        self._server = smtplib.SMTP(self._smtp_server, self._smtp_server_port)
        self._server.ehlo()
        self._server.starttls()
        self._server.ehlo()
        msg = MIMEMultipart('alternative')
        msg['From'] = self._fromaddr
        msg['To'] = ", ".join(toaddr_list)
        msg['Subject'] = subject
        text = MIMEText(text_part, 'plain')
        html = MIMEText(html_part, 'html')
        msg.attach(text)
        msg.attach(html)
        try:
            self._server.login(self._fromaddr, self._password)
            self._server.sendmail(self._fromaddr, toaddr_list, msg.as_string())
        except Exception as e:
            print("AutoscanApp EmailClient: email not sent", e)
            self._server.quit()

class SmsClient(object):
    """
    SMS Client for interacting with the SMS external subsustem.
    """

    def __init__(self, account_sid, auth_token):
        self._client = Client(account_sid, auth_token)

    def send_sms_alert(self, to_number, from_number, body):
        try:
            sms_result = self._client.api.account.messages.create(

                to = to_number,
                from_= from_number,
                body = body)

            print("SmsClient send_sms_alert: ", sms_result.sid)
        except Exception as e:
            print("SmsClient send_sms_alert Exception: ", e)