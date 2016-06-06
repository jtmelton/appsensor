var apiBaseUrl = $('#ctx').text();

function keepalive() {
	// 14 mins * 60 * 1000
	setInterval(
		function(){
		   $.get(apiBaseUrl + '/ping');
		}
	, 840000); 
}

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

function toCardinal(selectedTimeSpan) {
  	var cardinal;
  	
  	if (selectedTimeSpan === 'HOUR') {
  		cardinal = 5;
	} else if (selectedTimeSpan === 'SHIFT') {
		cardinal = 4;
	} else if (selectedTimeSpan === 'DAY') {
		cardinal = 3;
	} else if (selectedTimeSpan === 'WEEK') {
		cardinal = 2
	} else {
		cardinal = 1;
	}
  	
  	return cardinal;
}

function prettyPrint(data) {
	return JSON.stringify(data, null, 4);
}