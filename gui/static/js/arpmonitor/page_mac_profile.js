if( typeof pageCode !=  "undefined" ) {
  pageCode = undefined;
};

pageCode = function() {

  function GetURLParameter(sParam)
  {
    var sPageURL = window.location.search.substring(1);
    var sURLVariables = sPageURL.split('&');
    for (var i = 0; i < sURLVariables.length; i++) 
    {
        var sParameterName = sURLVariables[i].split('=');
        if (sParameterName[0] == sParam) 
        {
            return sParameterName[1];
        }
    }
  }

  var mac = GetURLParameter('mac'); 

  $("#macaddr").text( mac );
  $("a[href='http://arpmonitor_reset_mac/']").attr('href', '/arpmonitor/function/mac/reset/' + mac)

  var mac_ipv4_all = $('#mac_ipv4_all').dataTable( {
		"bProcessing": true,
                'iDisplayLength': 16,
                "bPaginate": false,
                "aaSorting": [ [0,'desc'] ],
		"sAjaxSource": '/arpmonitor/json/mac/ipv4/all/' + mac
  } );

  var mac_fqdn_all= $('#mac_fqdn_all').dataTable( {
                "bProcessing": true,
                'iDisplayLength': 16,
                "bPaginate": false,
                "aaSorting": [ [0,'desc'] ],
                "sAjaxSource": '/arpmonitor/json/mac/hostname/all/' + mac
  } );

  var mac_fqdn_all = $('#mac_scan_last').dataTable( {
                "bProcessing": true,
                'iDisplayLength': 32,
                "bPaginate": false,
                "aaSorting": [ [0,'desc'] ],
                "sAjaxSource": '/arpmonitor/json/mac/scan/latest/' + mac
  } );

  // Flot related
  var options_lines = {
    lines: { show: true, fill: true },
    points: { show: false },
    xaxis: { mode: "time",
             timezone: "browser"
           }
    };

   var options_bars = {
    lines: { show: true, fill: true },
    //bars: { show: true, fill: false, lineWidth: 8 },
    points: { show: false },
    xaxis: { mode: "time",
             timezone: "browser"
           }
    };


  var data_week = [];
  var data_day = [];
  var data_hour = [];
  var placeholder_week = $("#flot_week");
  var placeholder_day = $("#flot_day");
  var placeholder_hour = $("#flot_hour");
  var dataurl = '/arpmonitor/json/mac/arp/stats/';

  placeholder_week.resize(function () {
    $(".message").text("Placeholder is now "
    + $(this).width() + "x" + $(this).height()
    + " pixels");
  });

  placeholder_day.resize(function () {
    $(".message").text("Placeholder is now "
    + $(this).width() + "x" + $(this).height()
    + " pixels");
  });

  placeholder_hour.resize(function () {
    $(".message").text("Placeholder is now "
    + $(this).width() + "x" + $(this).height()
    + " pixels");
  });


  $.plot( placeholder_week, data_week, options_lines );
  $.plot( placeholder_day, data_day, options_lines );
  $.plot( placeholder_hour, data_hour, options_bars );

  var alreadyFetched_week = {};
  var alreadyFetched_day = {};
  var alreadyFetched_hour = {};

  function fetchWeek( mac, timestamp ) {
    function onDataReceived(series) {
      if (!alreadyFetched_week[series.label]) {
        alreadyFetched_week[series.label] = true;
        data_week.push(series);
      }
      $.plot(placeholder_week, data_week, options_lines );
    }
    $.ajax({
      url: dataurl + mac + "," + timestamp,
      method: 'GET',
      dataType: 'json',
      cache: false,
      success: onDataReceived
    });
  }

  function fetchDay( mac, timestamp ) {
    function onDataReceived(series) {
      if (!alreadyFetched_day[series.label]) {
        alreadyFetched_day[series.label] = true;
        data_day.push(series);
      }
      $.plot(placeholder_day, data_day, options_lines );
    }
    $.ajax({
      url: dataurl + mac + "," + timestamp,
      method: 'GET',
      dataType: 'json',
      cache: false,
      success: onDataReceived
    });
  }

  function fetchHour( mac, timestamp ) {
    function onDataReceived(series) {
      if (!alreadyFetched_hour[series.label]) {
        alreadyFetched_hour[series.label] = true;
        data_hour.push(series);
      }
      $.plot(placeholder_hour, data_hour, options_bars );
    }
    $.ajax({
      url: dataurl + mac + "," + timestamp,
      method: 'GET',
      dataType: 'json',
      cache: false,
      success: onDataReceived
    });
  }

  function fetchASK( mac ) {
    function onDataReceived(series) {
      $("#mac_active").text( series.active );      
      $("#mac_session").text( Math.round( series.session / 60 )
         + " minutes / " 
         + Math.round( ( series.session / 3600 ) * 100) / 100 
         + " hours" );      
      $("#mac_known_since").text( series.known_since );      
    }
    $.ajax({
      url: "/arpmonitor/json/mac/details/" + mac,
      method: 'GET',
      dataType: 'json',
      cache: false,
      success: onDataReceived
    });
  }

  function fetchRadarChartData( mac ) {
    function onDataReceived(series) {
      drawRadarChart1( series );
    }
    $.ajax({
      url: "/arpmonitor/json/mac/ai/score/" + mac,
      method: 'GET',
      dataType: 'json',
      cache: false,
      success: onDataReceived
    });
  }


  function drawRadarChart1( series ) {
    var radarChartData = {
      labels : series.score_legend,
      /* max data 
         this radarchart has error, need to compensate with 100,0 */
      datasets : [
        {
          fillColor : "rgba(220,220,220,0)",
          strokeColor : "rgba(151,187,205,0)",
          pointColor : "rgba(151,187,205,0)",
          pointStrokeColor : "#fff",
          data : series.score_max
        },
        /* real data */
        {
          fillColor : "rgba(151,187,205,0.5)",
          strokeColor : "rgba(220,220,220,1)",
          pointColor : "rgba(220,220,220,1)",
          pointStrokeColor : "#ff0000",
          data : series.score_real
        },
      ]
    };

    var radarChartOptions = {
      pointDotRadius : 8,
      animationSteps : 1024,
    };

    var ctx = $("#radarchart1").get(0).getContext("2d");
    var myNewChart = new Chart(ctx);
    new Chart(ctx).Radar(radarChartData,radarChartOptions);

  }

  function netflow( mac ) {
    function onDataReceived(series) {
      var data = {
        nodes: series.nodes,
        edges: series.edges
      };
      var options = {
        width: '100%',
        height: '800px',
        color: 'rgba(151,187,205,0.5)',
        stabilize: 'false',
        stabilizationIterations: 10,
        physics: {
          barnesHut: {
            enabled: true,
            gravitationalConstant: -1800,
            centralGravity: 0.3,
            springLength: 75,
            springConstant: 0.02,
            damping: 0.09
          }
        }
      };
      var container = document.getElementById('vis1');
      var graph = new vis.Graph(container, data, options);
    }
    $.ajax({
      url: '/arpmonitor/json/mac/netflow/?mac=' + mac,
      method: 'GET',
      dataType: 'json',
      cache: false,
      success: onDataReceived
    });
  }

  function updateAll() {
    fetchASK( mac ); // fetch details
    fetchWeek( mac, 604800 ); // a week
    fetchDay( mac, 86400 ); // a day
    fetchHour( mac, 3600 ); // hour
    fetchRadarChartData( mac ); // ai
    netflow( mac ); // netflow fetch
  }

  updateAll();
}

pageCode();

