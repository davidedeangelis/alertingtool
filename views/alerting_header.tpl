<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Alerting Tool</title>
    <link rel="stylesheet" href="../css/jquery-ui.css">
    <link rel="stylesheet" href="../css/jquery-ui.theme.css">
    <script src="../js/jquery.js"></script>
    <script src="../js/jquery-ui.js"></script>
    <link rel="stylesheet" type="text/css" href="https://cdn.datatables.net/1.10.16/css/jquery.dataTables.min.css">
    <script type="text/javascript" language="javascript" src="https://cdn.datatables.net/1.10.16/js/jquery.dataTables.min.js"></script>
    <link rel="stylesheet" href="../css/tables_custom.css">
    <script>
      $( function() {
        $( "#tabs" ).tabs({
          beforeLoad: function( event, ui ) {
            ui.jqXHR.fail(function() {
              ui.panel.html(
                "Couldn't load this tab. We'll try to fix this asap." );
            });
          }
        });
      } );

      $( function() {
        $('input[type="checkbox"]').checkboxradio({
          icon: false
        });
      } );
    </script>
    </head>
    <body>
        <div id="tabs">
            <ul>
                <li><a href="#tabs-1">Home</a></li>
                <li><a href="alerting/scans">Scans</a></li>
                <li><a href="alerting/alerts">Alerts</a></li>
                <li><a href="alerting/ssls">SSL</a></li>
            </ul>
            <div id="tabs-1">
                <h1>Alerting Tool</h1>
                <form role="form" method="post" action="/alerting/home/scan/">
                    <table>
                        <td>
                            <h3>Status</h3>
                            %status = 'Stopped' if data['status'] else 'Running'
                            <p>{{status}}</p>
                            <h3>Configuration</h3>
                            <div>
                                <input type="text" name="network" class="form-control" placeholder="e.g. 192.168.1.0" value="192.168.222.0" required>
                                <label for="network">Network</label><br>
                                <input type="number" name="mask" class="form-control" placeholder="e.g. 24" value="25" required>
                                <label for="subnet_mask">Subnet Mask</label><br>
                                <input type="number" name="interval" class="form-control" placeholder="e.g 300 seconds" value=500 required>
                                <label for="scan_interval">Scan Interval in Seconds</label><br>
                             </div>
                            <h3>Alerting</h3>
                            <div>
                                <h2>Email</h2>
                                <fieldset>
                                    <legend>Alert if: </legend>
                                    <label for="email_missing_hosts">Missing Hosts</label>
                                    <input type="checkbox" name="email_missing_hosts" id="email_missing_hosts" checked>
                                    <label for="email_new_hosts">New Hosts</label>
                                    <input type="checkbox" name="email_new_hosts" id="email_new_hosts">
                                    <label for="email_missing_ports">Missing Ports</label>
                                    <input type="checkbox" name="email_missing_ports" id="email_missing_ports" checked>
                                    <label for="email_new_ports">New Ports</label>
                                    <input type="checkbox" name="email_new_ports" id="email_new_ports">
                                    <label for="email_vulns">Service Vulnerabilities</label>
                                    <input type="checkbox" name="email_vulns" id="email_vulns" checked>
                                    <label for="email_ssl">SSL Anomalies</label>
                                    <input type="checkbox" name="email_ssl" id="email_ssl" checked>
                                </fieldset>
                                <h2>Sms</h2>
                                <fieldset>
                                    <legend>Alert if: </legend>
                                    <label for="sms_missing_hosts">Missing Hosts</label>
                                    <input type="checkbox" name="sms_missing_hosts" id="sms_missing_hosts" checked>
                                    <label for="sms_new_hosts">New Hosts</label>
                                    <input type="checkbox" name="sms_new_hosts" id="sms_new_hosts">
                                    <label for="sms_missing_ports">Missing Ports</label>
                                    <input type="checkbox" name="sms_missing_ports" id="sms_missing_ports" checked>
                                    <label for="sms_new_ports">New Ports</label>
                                    <input type="checkbox" name="sms_new_ports" id="sms_new_ports">
                                    <label for="sms_vulns">Service Vulnerabilities</label>
                                    <input type="checkbox" name="sms_vulns" id="sms_vulns" checked>
                                    <label for="sms_ssl">SSL Anomalies</label>
                                    <input type="checkbox" name="sms_ssl" id="sms_ssl" checked>
                                </fieldset>
                            </div>
                        </td>
                    </table>
                    <td>
                        <input type="submit" class="btn btn-default" name = "start" value="start" />
                        <input type="submit" class="btn btn-default" name = "stop" value="stop" />
                    </td>
                </form>
            </div>
        </div>
    </body>
</html>