if( typeof pageCode !=  "undefined" ) {
  pageCode = undefined;
};

pageCode = function() {
  var mac_active = $('#engine_active').dataTable( {
                "oLanguage": { "sLoadingRecords": '<center><img src=\"/img/loading_triangles.gif\"'
                               + ' width=\"160\" alt=\"Please wait - loading...\"></a></center>' }, 
                "paging": false,
                "bPaginate": false,
		"bProcessing": true,
                //"iDisplayLength": 64,
                "aaSorting": [ [0,'desc'] ],
		"sAjaxSource": '/arpmonitor/json/mac/list/active/complete/',
                "aoColumnDefs": [ 
                  {
                    "aTargets": [ 0 ], // Column to target
                    "mRender": function ( data, type, full ) {
                      // 'full' is the row's data object, and 'data' is this column's data
                      // e.g. 'full[0]' is the comic id, and 'data' is the comic title
                      return '<a href="/arpmonitor/mac/profile/?mac=' + full[0] +  '"' 
                              + 'target="_' + full[0] + '"' + '>' + data + '</a>';
                    }
                  }
                ]
  } );

  // not used
  function update() {
    mac_active.fnReloadAjax(); 
  };
};

pageCode();

