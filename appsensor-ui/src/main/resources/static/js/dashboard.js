var socket;
var client;

function addActivityMessage(element) {
	var tableRef = document.getElementById('dashboard-activity-log');
	
	//delete last row if table too big
	if(tableRef.rows.length > 10) {
		tableRef.deleteRow(tableRef.rows.length -1)
	}
	
	//console.log('num rows = ' + tableRef.rows.length);
	
	var newRow = tableRef.insertRow(1);
	
	var cType = newRow.insertCell(0);
	var txtType = document.createTextNode(element.type);
	cType.appendChild(txtType);
	
	var cDetPt = newRow.insertCell(1);
	var txtDetPt = document.createTextNode(element.category);
	cDetPt.appendChild(txtDetPt);
	
	var cUser = newRow.insertCell(2);
	var txtUser = document.createTextNode(element.from);
	cUser.appendChild(txtUser);
	
	var cDetSys = newRow.insertCell(3);
	var txtDetSys = document.createTextNode(element.to);
	cDetSys.appendChild(txtDetSys);
	
	var cTS = newRow.insertCell(4);
	var txtTS = document.createTextNode(element.timestamp);
	cTS.appendChild(txtTS);
}

// helper since events and attacks look the same
function logEventOrAttack(type, message) {
	var data = JSON.parse(message.body);
    
    var user = data.user;
    var detectionPoint = data.detectionPoint;
    var detectionSystem = data.detectionSystem;
    
    var composed = {};
    
    composed.type = type;
    composed.category = detectionPoint.label + ' (' + detectionPoint.category + ')' ;
    composed.timestamp = data.timestamp;
    
    var fromIpAddress = (user.ipAddress) ? ' (' + user.ipAddress.address + ')' : ' (no IP Address)';
	var fromGeo = (user.ipAddress && user.ipAddress.geoLocation) ? 
			' (' + user.ipAddress.geoLocation.latitude + ' / ' + user.ipAddress.geoLocation.longitude + ')' : 
				' (no geo)';
	var toIpAddress = (detectionSystem.ipAddress) ? ' (' + detectionSystem.ipAddress.address + ')' : ' (no IP Address)';
	var toGeo = (detectionSystem.ipAddress && detectionSystem.ipAddress.geoLocation) ? 
			' (' + detectionSystem.ipAddress.geoLocation.latitude + ' / ' + detectionSystem.ipAddress.geoLocation.longitude + ')' : 
				' (no geo)';
	
	composed.from = user.username + fromIpAddress + fromGeo;
    composed.to = detectionSystem.detectionSystemId + toIpAddress + toGeo;
    
	addActivityMessage(composed);
}

function subscribeOnSuccess(frame) {
	client.subscribe("/events", function(message) {
		logEventOrAttack('Event', message);    
	});

	client.subscribe("/attacks", function(message) {
		logEventOrAttack('Attack', message);
	});
  
	client.subscribe("/responses", function(message) {
	  	var response = JSON.parse(message.body);
	  	
	    var user = response.user;
	    var detectionSystem = response.detectionSystem;
	    
	    var composed = {};
	    
	    composed.type = 'Response';
	    
	    var responseInterval = (response.interval) ? ' ( effective for ' + response.interval.duration + ' ' + response.interval.unit + ')' : ''
	    var responseDescription = response.action + responseInterval;
	    
	    composed.category = responseDescription;	
	    composed.timestamp = event.timestamp;
	    
	    // for a response, to/from are reversed
	    var toIpAddress = (user.ipAddress) ? ' (' + user.ipAddress.address + ')' : ' (no IP Address)';
    	var toGeo = (user.ipAddress && user.ipAddress.geoLocation) ? 
    			' (' + user.ipAddress.geoLocation.latitude + ' / ' + user.ipAddress.geoLocation.longitude + ')' : 
    				' (no geo)';
    	var fromIpAddress = (detectionSystem.ipAddress) ? ' (' + detectionSystem.ipAddress.address + ')' : ' (no IP Address)';
    	var fromGeo = (detectionSystem.ipAddress && detectionSystem.ipAddress.geoLocation) ? 
    			' (' + detectionSystem.ipAddress.geoLocation.latitude + ' / ' + detectionSystem.ipAddress.geoLocation.longitude + ')' : 
    				' (no geo)';
    	
    	composed.from = detectionSystem.detectionSystemId + fromIpAddress + fromGeo;
	    composed.to = user.username + toIpAddress + toGeo;
	    
    	addActivityMessage(composed);
	});
}

function reconnectOnFailure(error) {
    console.log('STOMP: ' + error);
    setTimeout(stompConnect, 10000);
    console.log('STOMP: Reconecting in 10 seconds');
};

function stompConnect() {
    console.log('STOMP: Attempting connection');
    // recreate the stompClient to use a new WebSocket
    socket = new SockJS('/appsensor-websocket');
    client = Stomp.over(socket);
    client.connect('unused_user', 'unused_password', subscribeOnSuccess, reconnectOnFailure);
}

function keepalive() {
	// 14 mins * 60 * 1000
	setInterval(
		function(){
		   $.get(apiBaseUrl + '/ping');
		}
	, 840000); 
}

function activateSlider() {
	var items =[ 'Month','Week','Day','Shift', 'Hour'];
	var s = $("#timeline-slider");

	s.slider({
	  min:1,
	  max:items.length,
	  slide: function( event, ui ) {
		  console.log('user selected: "' + items[ui.value - 1] + '"');
      }
	});

	var oneBig = 100 / (items.length - 1);

	$.each(items, function(key,value){
	  var w = oneBig;
	  if(key === 0 || key === items.length-1)
	    w = oneBig/2;
	    
	  $("#timeline-legend").append("<label id='"+value+"-slider-label' style='width: "+w+"%'>"+value+"</laben>");
	});
	
}

function buildStackedBarChart() {
	
	var now = moment();
	
	var timestamp = now.subtract(7, 'hours').format()
	
	$.ajax({
	      url: apiBaseUrl + '/api/events/grouped?earliest=' + timestamp + '&slices=10',
	      success: function(data) {
	    	  console.log('queried on ' + apiBaseUrl + '/api/events/grouped?earliest=' + timestamp + '&slices=7');
	          var viewObject = data;
	          
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
	    	  alert('Failure contacting appsensor service for loading events.');
	      }
	  });
	
	$("#last-updated-time").text(now.format("YYYY/MM/DD, HH:mm"));
	
	$("#Month-slider-label").html('Month <span class="badge" title="10 events / 5 responses">10 / 5</span>');
	$("#Week-slider-label").html('Week <span class="badge" title="9 events / 4 responses">9 / 4</span>');
	$("#Day-slider-label").html('Day <span class="badge" title="8 events / 3 responses">8 / 3</span>');
	$("#Shift-slider-label").html('Shift <span class="badge" title="7 events / 2 responses">7 / 2</span>');
	$("#Hour-slider-label").html('Hour <span class="badge" title="6 events / 1 responses">6 / 1</span>');
	
	 
}

function setToArray(set) {
  var it = set.values(),
      ar = [],
      val;

  while(val = it.next().value) {
    ar.push(val);
  }

  return ar;
}

$(function() {
	stompConnect();
	keepalive();
	activateSlider();
	buildStackedBarChart();
});
