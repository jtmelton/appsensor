var socket;
var client;

function subscribeOnSuccess(frame) {
	  client.subscribe("/events", function(message) {
		    var event = JSON.parse(message.body);
		    
		    var user = event.user;
		    var detectionPoint = event.detectionPoint;
		    var detectionSystem = event.detectionSystem;
		    
		    var composed = {};
		    
		    composed.type = 'Event';
		    composed.category = detectionPoint.label + ' (' + detectionPoint.category + ')' ;
		    composed.timestamp = event.timestamp;
		    
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
		    
		    if ('ipAddress' in user && user.ipAddress && 
		    		'geoLocation' in user.ipAddress && user.ipAddress.geoLocation &&
		    		'ipAddress' in detectionSystem && detectionSystem.ipAddress && 
		    		'geoLocation' in detectionSystem.ipAddress && detectionSystem.ipAddress.geoLocation) {
		    	composed.origin = {};
		    	composed.origin.latitude = user.ipAddress.geoLocation.latitude;
		    	composed.origin.longitude = user.ipAddress.geoLocation.longitude;
		    	composed.destination = {};
		    	composed.destination.latitude = detectionSystem.ipAddress.geoLocation.latitude;
		    	composed.destination.longitude = detectionSystem.ipAddress.geoLocation.longitude;
		    	composed.options = {};
		    	composed.options.strokeColor = 'yellow';
		    	composed.name = 'Event received of type "' + composed.category + '"<br /> from user "' + composed.from + '"<br /> to detection system "' + composed.to + '"<br />';
		    	composed.radius = 10;
		    	composed.fillKey = 'eventFill';
		    	composed.latitude = detectionSystem.ipAddress.geoLocation.latitude;
		    	composed.longitude = detectionSystem.ipAddress.geoLocation.longitude;
		    	
		    	add(composed, events, bubbleEvents);
		    } else {
		    	composed.type = 'Unmapped Event';
		    	
		    	addActivityMessage(composed);
		    }
		    
	  });
	
	  client.subscribe("/attacks", function(message) {
		  	var attack = JSON.parse(message.body);
		    
		    var user = attack.user;
		    var detectionPoint = attack.detectionPoint;
		    var detectionSystem = attack.detectionSystem;
		    
		    var composed = {};
		    
		    composed.type = 'Attack';
		    composed.category = detectionPoint.label + ' (' + detectionPoint.category + ')' ;
		    composed.timestamp = event.timestamp;
		    
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
		    
		    if ('ipAddress' in user && user.ipAddress && 
		    		'geoLocation' in user.ipAddress && user.ipAddress.geoLocation &&
		    		'ipAddress' in detectionSystem && detectionSystem.ipAddress && 
		    		'geoLocation' in detectionSystem.ipAddress && detectionSystem.ipAddress.geoLocation) {
		    	composed.origin = {};
		    	composed.origin.latitude = user.ipAddress.geoLocation.latitude;
		    	composed.origin.longitude = user.ipAddress.geoLocation.longitude;
		    	composed.destination = {};
		    	composed.destination.latitude = detectionSystem.ipAddress.geoLocation.latitude;
		    	composed.destination.longitude = detectionSystem.ipAddress.geoLocation.longitude;
		    	composed.options = {};
		    	composed.options.strokeColor = 'red';
		    	composed.name = 'Attack received of type "' + composed.category + '"<br /> from user "' + composed.from + '"<br /> to detection system "' + composed.to + '"<br />';
		    	composed.radius = 10;
		    	composed.fillKey = 'attackFill';
		    	composed.latitude = detectionSystem.ipAddress.geoLocation.latitude;
		    	composed.longitude = detectionSystem.ipAddress.geoLocation.longitude;
		    	
		    	add(composed, attacks, bubbleAttacks);
		    } else {
		    	composed.type = 'Unmapped Attack';
		    	
		    	addActivityMessage(composed);
		    }
		  
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
		    
		    if ('ipAddress' in user && user.ipAddress && 
		    		'geoLocation' in user.ipAddress && user.ipAddress.geoLocation &&
		    		'ipAddress' in detectionSystem && detectionSystem.ipAddress && 
		    		'geoLocation' in detectionSystem.ipAddress && detectionSystem.ipAddress.geoLocation) {
		    	composed.destination = {};
		    	composed.destination.latitude = user.ipAddress.geoLocation.latitude;
		    	composed.destination.longitude = user.ipAddress.geoLocation.longitude;
		    	composed.origin = {};
		    	composed.origin.latitude = detectionSystem.ipAddress.geoLocation.latitude;
		    	composed.origin.longitude = detectionSystem.ipAddress.geoLocation.longitude;
		    	composed.options = {};
		    	composed.options.strokeColor = 'green';
		    	composed.name = 'Response received of type "' + composed.category + '"<br /> from detection system "' + composed.from + '"<br /> to user "' + composed.to + '"<br />';
		    	composed.radius = 10;
		    	composed.fillKey = 'responseFill';
		    	composed.latitude = user.ipAddress.geoLocation.latitude;
		    	composed.longitude = user.ipAddress.geoLocation.longitude;
		    	
		    	add(composed, responses, bubbleResponses);
		    } else {
		    	composed.type = 'Unmapped Response';
		    	
		    	addActivityMessage(composed);
		    }
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
	setInterval(
		function(){
		   $.get(apiBaseUrl + '/ping');
		}
	, 840000); 	// 14 mins * 60 * 1000
}

$(function() {
	stompConnect();
	keepalive();
});

// end websockets, start mapping

var map = new Datamap({
    element: document.getElementById('mapcontainer'),
	fills: {
	    defaultFill: '#424242',
	    eventFill: 'yellow',
	    attackFill: 'red',
	    responseFill: 'green'
    },
	geographyConfig: {
	    dataUrl: null, //if not null, datamaps will fetch the map JSON (currently only supports topojson)
		borderWidth: 1,
		borderColor: '#2E2E2E',
		popupOnHover: true, //disable the popup while hovering
		highlightOnHover: true,
		highlightFillColor: '#6E6E6E',
		highlightBorderColor: '#6E6E6E',
		highlightBorderWidth: 2
	},
	arcConfig: {
  		strokeColor: '#6E6E6E',
  		strokeWidth: 5,
  		arcSharpness: 3,
  		animationSpeed: 10000
	}
});

var events = []
var attacks = []
var responses = []
var bubbleEvents = []
var bubbleAttacks = []
var bubbleResponses = []

function queueDeletion(dataArray, timeout) {
	window.setTimeout(
		function() {
	       	if(dataArray.length > 0) {
				// delete oldest element
				var timedOut = dataArray.shift();
				//console.log("shifted " + JSON.stringify(timedOut));
			}
	    }, timeout);
}

function add(element, dataArray, bubbleArray) {
	dataArray.push(element);
	bubbleArray.push(element);
	queueDeletion(dataArray, 20000);
	queueDeletion(bubbleArray, 10000);
	addActivityMessage(element);
}

function addActivityMessage(element) {
	var tableRef = document.getElementById('activity_log');
	
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

function popoverView(geo, data) {
	return '<div class="hoverinfo"><strong>' + data.name + '</strong><hr />' + 
		'<strong>From: </strong>' + 
		'[' + data.origin.latitude + '/' + data.origin.longitude + ']<br />' +
		'<strong>To: </strong>' + 
		'[' + data.destination.latitude + '/' + data.destination.longitude + ']<br />' +
		'</div>';   
}

function displayData() {
	window.setTimeout(function() {
		var joined = events.concat(attacks, responses);
		var bubblejoined = bubbleEvents.concat(bubbleAttacks, bubbleResponses);
	
		map.arc( joined , {strokeWidth: 2} );
		
		window.setTimeout(function() {
			map.bubbles(bubblejoined, {popupTemplate: popoverView});
		}, 10000);
		
		displayData();
	    }, 1750);
}

var eventCounter = 0;
var attackCounter = 0;
var responseCounter = 0;                    

function goFullScreen() {
	$("#appsensor-navbar").hide();
	$("#geo_full_screen").hide();
	$("#geo_normal_screen").show();
}

function goNormalScreen() {
	$("#appsensor-navbar").show();
	$("#geo_normal_screen").hide();
	$("#geo_full_screen").show();
}

$(function() {
	// override bg-color for body
    $('body').css('background-color', '#2E2E2E !important');
    
    $("#geo_full_screen").click(function(){
        goFullScreen();
    });
    $("#geo_normal_screen").click(function(){
        goNormalScreen();
    });
    
    $("#geo_normal_screen").hide();
	
	displayData();
});
