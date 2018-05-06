<link rel="stylesheet" href="../css/tables_custom.css">

<script type="text/javascript" language="javascript" class="init">

  $("#scandate" ).selectmenu ({
        change:function( event,ui ) {
        data = $(this).val();

        $.ajax({
            url: '/alerting/ajax/scans/',
            data: "data=" + data,
            success: function (data) {
                $('#scan-table').replaceWith(data)
            }
        }).error(function() {
            $('#scans_results').text('An error occured');
        });
        }
    });
</script>

<div id="scans_results">
    <h1>Scans</h1>
    <br>
    <div class="container">

        <form action="#" id="scanselectform">
            <fieldset id="fieldset">
                <select name="scandate" id="scandate">
                    <option selected="selected">Select Scan Date</option>
                    %for scantime in time_scans_list:
                        <option>{{scantime}}</option>
                    % end
                </select>
                <br>
                <br>
                <table id="scan-table" style="display:none"></table>
            </fieldset>
        </form>
    </div>
</div>