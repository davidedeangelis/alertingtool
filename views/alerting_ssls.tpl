<link rel="stylesheet" href="../css/tables_custom.css">

<script type="text/javascript" language="javascript" class="init">

  $("#ssldate").selectmenu ({
        change:function( event,ui ) {
        data = $(this).val();

        $.ajax({
            url: '/alerting/ajax/ssls/',
            data: "data=" + data,
            success: function (data) {
               $('#ssls-table').replaceWith(data)
            }
        }).error(function() {
            $('#ssls_results').text('An error occured');
        });
        }
    });
</script>

<div id="ssls_results">
    <h1>SSL Analysis</h1>
    <br>
    <div class="container">

        <form action="#" id="sslselectform">

            <fieldset id="fieldset">
                <select name="ssldate" id="ssldate">
                    <option selected="selected">Select SSL Analysis Date</option>
                    %for scan_time in time_ssls_list:
                        <option>{{scan_time}}</option>
                    % end
                </select>
                <br>
                <br>
                <table id="ssls-table" style="display:none"></table>
            </fieldset>
        </form>
    </div>
</div>
