var Alerting = Alerting || {};

Alerting.tool = (function($) {

    function
    var json = undefined;
        $.ajax({
                type: "GET",
                url: "./ajax/alerts",
                context: "",
                dataType: "json"
            }).done(function(response) {

                json = response
            })

        $(function() {
          $('#json').JSONView(json);

          $('#collapse-btn').on('click', function() {
            $('#json').JSONView('collapse');
          });

          $('#expand-btn').on('click', function() {
            $('#json').JSONView('expand');
          });

          $('#toggle-btn').on('click', function() {
            $('#json').JSONView('toggle');
          });

          $('#toggle-level1-btn').on('click', function() {
            $('#json').JSONView('toggle', 1);
          });

          $('#toggle-level2-btn').on('click', function() {
            $('#json').JSONView('toggle', 2);
          });
        });
})(jQuery);

$(document).ready(function() {

});