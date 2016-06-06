
function updateView(data) {
	// loop over each record, updating view as we find the right record
	$.each(data, function(index, obj) {
		var objId = '#' + obj.unit.toLowerCase() + '-' + obj.type.toLowerCase() + 's';
		var cssClass = 'trend-' + obj.direction.toLowerCase();
		var count = obj.count;
		
		$(objId).removeClass("trend-same trend-lower trend-higher");
		$(objId).addClass(cssClass);
		$(objId).text(count);
		
		var now = moment();
		var monthAgo = moment().subtract(1, 'months');
		var weekAgo = moment().subtract(1, 'weeks');
		var dayAgo = moment().subtract(1, 'days');
		var shiftAgo = moment().subtract(8, 'hours');
		var hourAgo = moment().subtract(1, 'hours');
		
		$("#month-time-span").text(monthAgo.format("D MMM") + ' - ' + now.format("D MMM"));
		$("#week-time-span").text(weekAgo.format("D MMM") + ' - ' + now.format("D MMM"));
		$("#day-time-span").text(dayAgo.format("D MMM") + ' - ' + now.format("D MMM"));
		$("#shift-time-span").text(shiftAgo.format("HH:mm") + ' - ' + now.format("HH:mm"));
		$("#hour-time-span").text(hourAgo.format("HH:mm") + ' - ' + now.format("HH:mm"));
		
		$("#last-updated-time").text(now.format("YYYY/MM/DD, HH:mm"));
	});
	
}

// completes ajax then calls load responses on success
function loadEvents(timestamp) {
	$.ajax({
	      url: apiBaseUrl + '/api/trends/by-time-frame',
	      success: function(data) {
	          updateView(data)
	      },
	      error: function(data) {
	    	  alert('Failure contacting appsensor service for loading events.');
	      }
	  });
}

function loadData(firstTime) {
	if (firstTime) {
		var timestamp = moment().subtract(1,'months').toISOString();
		loadEvents(timestamp);
	}
	
	window.setTimeout(function() {
		var timestamp = moment().subtract(1,'months').toISOString();
		loadEvents(timestamp);

		loadData(false);
	    }, 60 * 1000);	//load every 60 seconds
}

$(function() {
	loadData(true);
});