if( typeof pageCode !=  "undefined" ) {
  pageCode = undefined;
};

pageCode = function() {
  var grid = {};

  var opts = {
    lines:            24,          // The number of lines to draw
    angle:            0.15,        // The length of each line
    lineWidth:        0.44,         // The line thickness
    pointer: {                     // * pointer *
      length:         0.64,        // The radius of the inner circle
      strokeWidth:    0.068,       // The rotation offset
      color:          '#309FFF'    // Fill color
    },
    limitMax:         'false',     // If true, the pointer will not go past the end of the gauge
    colorStart:       '#85CFF7',   // Colors
    colorStop:        '#7CA6BD',   // just experiment with them
    strokeColor:      '#E0E0E0',   // to see which ones work best for you
    generateGradient: false
  };

  function updateGauges() {
    $.getJSON('/arpmonitor/json/engine/realtime/gauges/', function(data) {
      for (var item in data) {
        if( typeof grid[ item ] != "undefined" ) {
          grid[ item ].maxValue = data[ item ].max;
          grid[ item ].set( data[ item ].val );
        } else {
          grid[ item ] = new Gauge( document.getElementById( item ) ).setOptions( opts );
          grid[ item ].setTextField( document.getElementById( item + "-textfield") );
          grid[ item ].animationSpeed = 22;
          grid[ item ].maxValue = data[ item ].max;
          grid[ item ].set( data[ item ].val );
        }
      };
    });
  };


  var options = {
    lines: { show: true, fill: false },
    points: { show: false },
    xaxis: { mode: "time" }
    };

  var data = [];
  var placeholder = $("#flot");
  var dataurl = '/arpmonitor/json/engine/statistics/arp/interface/';

  $.ajaxSetup({
    cache: false
  });

  placeholder.resize(function () {
    $(".message").text("Placeholder is now "
    + $(this).width() + "x" + $(this).height()
    + " pixels");
  });

  $.plot( placeholder, data, options );

  var alreadyFetched = {};

  function newFetch( iface ) {
    function onDataReceived(series) {
      if (!alreadyFetched[series.label]) {
        alreadyFetched[series.label] = true;
        data.push(series);
      }
      $.plot(placeholder, data, options);
    }
    $.ajax({
      url: dataurl + iface,
      method: 'GET',
      dataType: 'json',
      success: onDataReceived
    });
  }

  function updateFlot() {
    newFetch( "eth1" );
    newFetch( "eth2" );
    newFetch( "eth3" );
    newFetch( "eth4" );
  }

  function updateAll() {
    updateFlot();
    updateGauges();
  }

  updateAll();
  window.setInterval( updateAll, 60000 );

};

pageCode();

