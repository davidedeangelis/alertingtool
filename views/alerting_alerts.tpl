<link rel="stylesheet" href="../css/tables_custom.css">

<script type="text/javascript" language="javascript" class="init">

  $("#alertdate").selectmenu ({
        change:function( event,ui ) {
        data = $(this).val();

        $.ajax({
            url: '/alerting/ajax/alerts/',
            data: "data=" + data,
            success: function (data) {
               $('#alerts-table').replaceWith(data)
            }
        }).error(function() {
            $('#alerts_results').text('An error occured');
        });
        }
    });
</script>

<div id="alerts_results">
    <h1>Alerts</h1>
    <br>
    <div class="container">

        <form action="#" id="alertselectform">

            <fieldset id="fieldset">
                <select name="alertdate" id="alertdate">
                    <option selected="selected">Select Alert Date</option>
                    %for alerttime in time_alerts_list:
                        <option>{{alerttime}}</option>
                    % end
                </select>
                <br>
                <br>
                <table id="alerts-table" style="display:none"></table>
            </fieldset>
        </form>
    </div>
</div>
