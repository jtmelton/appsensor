function getTimestamp(selectedTimeSpan) {
	var now = moment();
  	var timestamp;
  	
  	if (selectedTimeSpan === 'HOUR') {
  		timestamp = now.subtract(1, 'hours').format();
	} else if (selectedTimeSpan === 'SHIFT') {
  		timestamp = now.subtract(8, 'hours').format();
	} else if (selectedTimeSpan === 'DAY') {
  		timestamp = now.subtract(1, 'days').format();
	} else if (selectedTimeSpan === 'WEEK') {
  		timestamp = now.subtract(1, 'weeks').format();
	} else {
  		timestamp = now.subtract(1, 'months').format();
	}
  	
  	return timestamp;
}

function findCount(timeUnit, category, trendItemArray) {
	for (var i in trendItemArray) {
		if (trendItemArray[i].unit === timeUnit && trendItemArray[i].type === category) {
			return trendItemArray[i].count;
		}
	}
	
	return -1;
}

$(function() {

  	var timestamp = getTimestamp('WEEK');
  
  	console.log('calling for ts: ' + timestamp);
  	console.log('calling at : ' + apiBaseUrl + '/api/points/IE1/all?earliest=' + timestamp + '&limit=5');
  	
    $.ajax({
      url: apiBaseUrl + '/api/detection-points/IE1/all?earliest=' + timestamp + '&limit=5',
      success: function(data) {
        
    	console.log('pulled data back and refreshed ui at ' + timestamp);
        
    	console.log('data is : ' + data);
        
      }.bind(this),
      error: function(xhr, status, err) {
        console.error(apiBaseUrl + '/api/dashboard/all?earliest=' + timestamp + '&limit=5&slices=10', status, err.toString());
      }.bind(this)
    });
			
//    Morris.Area({
//    	  element: 'area-example',
//    	  data: [
//    	    { y: '2006', a: 100 },
//    	    { y: '2007', a: 75 },
//    	    { y: '2008', a: 50 },
//    	    { y: '2009', a: 75 },
//    	    { y: '2010', a: 50 },
//    	    { y: '2011', a: 75 },
//    	    { y: '2012', a: 100 }
//    	  ],
//    	  xkey: 'y',
//    	  ykeys: ['a'],
//    	  labels: ['Some Fancy Label']
//    	});
//    
//    function displayMorris(viewObject) {
//  	  //clean up contents and start over
//    	  $("#category-count-graph").empty();
//  	  
//        var viewData = JSON.parse(viewObject.data);
//        var viewXKey = viewObject.xkey;
//        var viewYKeys = viewObject.ykeys;
//        var viewLabels = viewObject.labels;
//
//        Morris.Area({
//      	  element: 'category-count-graph',
//      	  data: JSON.parse(viewObject.data),
//      	  xkey: viewObject.xkey,
//      	  ykeys: viewObject.ykeys,
//      	  labels: viewObject.labels
//      	});
//  }
    
    $.ajax({
    	  url: apiBaseUrl + '/api/detection-points/IE1/grouped?earliest=' + timestamp + '&slices=10',
	      
	      success: function(viewObject) {

	    	  $("#area-example").empty();
	      	  
	          var viewData = JSON.parse(viewObject.data);
	          var viewXKey = viewObject.xkey;
	          var viewYKeys = viewObject.ykeys;
	          var viewLabels = viewObject.labels;

	          Morris.Area({
	        	  element: 'area-example',
	        	  data: JSON.parse(viewObject.data),
	        	  xkey: viewObject.xkey,
	        	  ykeys: viewObject.ykeys,
	        	  labels: viewObject.labels
	          });
	      },
	      error: function(data) {
	    	  console.log('Failure contacting appsensor service for loading updateSlider.');
	      }
	  });
    
    $.ajax({
	      url: apiBaseUrl + '/api/dashboard/by-time-frame',
	      
	      success: function(data) {

	    		var span;
	    		
	    	  	var monthEvents = findCount('MONTH', 'EVENT', data);
	    	  	var weekEvents = findCount('WEEK', 'EVENT', data);
	    	  	var dayEvents = findCount('DAY', 'EVENT', data);
	    	  	var shiftEvents = findCount('SHIFT', 'EVENT', data);
	    	  	var hourEvents = findCount('HOUR', 'EVENT', data);
	    	  	
	    	  	if (hourEvents > 0) {
	    	  		span = 'HOUR';
	    	  	} else if (shiftEvents > 0) {
	    	  		span = 'SHIFT';
	    	  	} else if (dayEvents > 0) {
	    	  		span = 'DAY';
	    	  	} else if (weekEvents > 0) {
	    	  		span = 'WEEK';
	    	  	} else {
	    	  		span = 'MONTH';
	    	  	}
	    	  	
	    	  	console.log('span is : ' + span);
	    	  	
//		  		initReact(span);
	      },
	      error: function(data) {
	    	  console.log('Failure contacting appsensor service for loading updateSlider.');
	      }
	  });
	
});