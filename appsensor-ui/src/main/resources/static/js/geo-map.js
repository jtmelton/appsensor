var socket;
var client;

function subscribeOnSuccess(frame) {
	  client.subscribe("/events", function(message) {
//	    console.log("saw event: " + message);
	    var event = JSON.parse(message.body);
//	    console.log(JSON.stringify(eventOriginal, null, 4));
//	    console.log(JSON.stringify(message, null, 4));
	    
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
	    	console.log('YES');
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
	    	console.log('NO');
	    	composed.type = 'Unmapped Event';
//	    	composed.origin.latitude = user.ipAddress.geoLocation.latitude;
//	    	composed.origin.longitude = user.ipAddress.geoLocation.longitude;
//	    	composed.destination.latitude = detectionSystem.ipAddress.geoLocation.latitude;
//	    	composed.destination.longitude = detectionSystem.ipAddress.geoLocation.longitude;
//	    	composed.options.strokeColor = 'yellow';
//	    	composed.name = 'Event received of type "' + composed.category + '"<br /> from user "' + composed.from + '"<br /> to detection system "' + composed.to + '"<br />';
//	    	composed.radius = 10;
//	    	composed.fillKey: 'eventFill',
//	    	composed.latitude: detectionSystem.ipAddress.geoLocation.latitude,
//	    	composed.longitude: detectionSystem.ipAddress.geoLocation.longitude
	    	//don't add event, but log activity message
	    	addActivityMessage(composed);
	    }
		    
		    
	    /*{
        origin: {
            latitude: 38.895111,
            longitude: -77.036667
        },
        destination: {
            latitude: 32.066667,
            longitude: 34.783333 
        },
    options: {
	strokeColor: 'yellow',
    },
    name: 'Event',
    radius: 10,
    fillKey: 'eventFill',
    latitude: 32.066667,
    longitude: 34.783333
    },*/
	    
//	    {
//	        "user": {
//	            "username": "frank",
//	            "ipAddress": {
//	                "address": "10.10.10.1",
//	                "geoLocation": {
//	                    "latitude": 37.596758,
//	                    "longitude": -121.647992
//	                }
//	            }
//	        },
//	        "detectionPoint": {
//	            "category": "Input Validation",
//	            "label": "IE2",
//	            "responses": []
//	        },
//	        "timestamp": "2015-07-01T02:03:25.296Z",
//	        "detectionSystem": {
//	            "detectionSystemId": "myclientgeoapp2",
//	            "ipAddress": {
//	                "address": "10.10.10.6",
//	                "geoLocation": {
//	                    "latitude": -7.471493,
//	                    "longitude": -47.248578
//	                }
//	            }
//	        },
	    
	    
	    
	    
	    
	  });
	
	  client.subscribe("/attacks", function(message) {
//		  console.log("saw attack: " + message);
	  });
	  
	  client.subscribe("/responses", function(message) {
//		  console.log("saw response: " + message);
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
		   $.get(apiBaseUrl + '/dashboard/ping');
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

var eventData = [
    /*{
        origin: {
            latitude: 38.895111,
            longitude: -77.036667
        },
        destination: {
            latitude: 32.066667,
            longitude: 34.783333 
        },
    options: {
	strokeColor: 'yellow',
    },
    name: 'Event',
    radius: 10,
    fillKey: 'eventFill',
    latitude: 32.066667,
    longitude: 34.783333
    },
    {
        origin: {
            latitude: 38.895111,
            longitude: -77.036667
        },
        destination: {
            latitude: 19.433333,
            longitude: -99.133333
        },
    options: {
	strokeColor: 'yellow',
    },
    name: 'Event',
    radius: 10,
    fillKey: 'eventFill',
    latitude: 19.433333,
    longitude: -99.133333
    }*/
];

var attackData = [
    /*{
        origin: {
            latitude: 38.895111,
            longitude: -77.036667
        },
        destination: {
            latitude: 9.933333,
            longitude: -84.083333
        },
    options: {
	strokeColor: 'red',
    },
    name: 'Attack',
    radius: 10,
    fillKey: 'attackFill',
    latitude: 9.933333,
    longitude: -84.083333
    },
    {
        origin: {
            latitude: 38.895111,
            longitude: -77.036667
        },
        destination: {
            latitude: 54.597,
            longitude: -5.93
        },
    options: {
	strokeColor: 'red',
    },
    name: 'Attack',
    radius: 10,
    fillKey: 'attackFill',
    latitude: 54.597,
    longitude: -5.93
    },
    {
        origin: {
            latitude: 38.895111,
            longitude: -77.036667
        },
        destination: {
            latitude: 52.516667,
            longitude: 13.383333 
        },
    options: {
	strokeColor: 'red',
    },
    name: 'Attack',
    radius: 10,
    fillKey: 'attackFill',
    latitude: 52.516667,
    longitude: 13.383333
    }*/
];

var responseData = [
    /*{
        origin: {
            latitude: 38.895111,
            longitude: -77.036667
        },
        destination: {
            latitude: 14.692778,
            longitude: -17.446667
        },
    options: {
	strokeColor: 'green',
    },
    name: 'Response',
    radius: 10,
    fillKey: 'responseFill',
    latitude: 14.692778,
    longitude: -17.446667
    },
    {
        origin: {
            latitude: 38.895111,
            longitude: -77.036667
        },
        destination: {
            latitude: -26.204444,
            longitude: 28.045556
        },
    options: {
	strokeColor: 'green',
    },
    name: 'Response',
    radius: 10,
    fillKey: 'responseFill',
    latitude: -26.204444,
    longitude: 28.045556
    },
    {
        origin: {
            latitude: 38.895111,
            longitude: -77.036667
        },
        destination: {
            latitude: -6.8,
            longitude: 39.283333 
        },
    options: {
	strokeColor: 'green',
    },
    name: 'Response',
    radius: 10,
    fillKey: 'responseFill',
    latitude: -6.8,
    longitude: 39.283333
    },
    {
        origin: {
            latitude: 38.895111,
            longitude: -77.036667
        },
        destination: {
            latitude: 59.329444,
            longitude: 18.068611
        },
    options: {
	strokeColor: 'green',
    },
    name: 'Response',
    radius: 10,
    fillKey: 'responseFill',
    latitude: 59.329444,
    longitude: 18.068611
    },
    {
        origin: {
            latitude: 38.895111,
            longitude: -77.036667
        },
        destination: {
            latitude: 59.95,
            longitude: 30.3
        },
    options: {
	strokeColor: 'green',
    },
    name: 'Response',
    radius: 10,
    fillKey: 'responseFill',
    latitude: 59.95,
    longitude: 30.3
    }*/
];

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

/*
function addActivityMessage(element) {
	var tableRef = document.getElementById('activity_log');
	
	//delete last row if table too big
	if(tableRef.rows.length > 10) {
		tableRef.deleteRow(tableRef.rows.length -1)
	}
	
	//console.log('num rows = ' + tableRef.rows.length);
	
	var newRow = tableRef.insertRow(1);
	
	var cType = newRow.insertCell(0);
	var txtType = document.createTextNode('Event');
	cType.appendChild(txtType);
	
	var cDetPt = newRow.insertCell(1);
	var txtDetPt = document.createTextNode('IE2' + ' ' + '(Input Validation)');
	cDetPt.appendChild(txtDetPt);
	
	var cUser = newRow.insertCell(2);
	var txtUser = document.createTextNode('suzy' + '[' + '1.2.3.4' + ']' + '(' + '13.784 / 93.6714' + ')');
	cUser.appendChild(txtUser);
	
	var cDash = newRow.insertCell(3);
	var txtDash = document.createTextNode(' --> ');
	cDash.appendChild(txtDash);
	
	var cDetSys = newRow.insertCell(4);
	var txtDetSys = document.createTextNode('myapp2' + '[' + '5.6.7.8' + ']' + '(' + '54.892 / 45.2168' + ')');
	cDetSys.appendChild(txtDetSys);
	
	var cTS = newRow.insertCell(5);
	var txtTS = document.createTextNode('2015-07-01T02:03:25.296Z');
	cTS.appendChild(txtTS);
}
*/
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
	
	var cDash = newRow.insertCell(3);
	var txtDash = document.createTextNode(' --> ');
	cDash.appendChild(txtDash);
	
	var cDetSys = newRow.insertCell(4);
	var txtDetSys = document.createTextNode(element.to);
	cDetSys.appendChild(txtDetSys);
	
	var cTS = newRow.insertCell(5);
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
		console.log('------|| 1 ||------');
		var joined = events.concat(attacks, responses);
		var bubblejoined = bubbleEvents.concat(bubbleAttacks, bubbleResponses);
	
		map.arc( joined , {strokeWidth: 2} );
		
		window.setTimeout(function() {
			map.bubbles(bubblejoined, {popupTemplate: popoverView});
		}, 10000);
		
		console.log('------|| 2 ||------');
		displayData();
		console.log('------|| 3 ||------');
	    }, 1750);
}

var eventCounter = 0;
var attackCounter = 0;
var responseCounter = 0;                    
/*
function loopEvents () {        
	setTimeout(function () {    
	      	var event = eventData[eventCounter];
	      	add(event, events, bubbleEvents);
	      	eventCounter++;                     
	      	if (eventCounter < eventData.length) {            
	      		loopEvents();             
	      	}                       
	}, 1750)
}

function loopAttacks () {        
	setTimeout(function () {    
	      	var attack = attackData[attackCounter];
	      	add(attack, attacks, bubbleAttacks);
	      	attackCounter++;                     
	      	if (attackCounter < attackData.length) {            
	      		loopAttacks();             
	      	}                       
	}, 1750)
}

function loopResponses () {        
	setTimeout(function () {    
	      	var response = responseData[responseCounter];
	      	add(response, responses, bubbleResponses);
	      	responseCounter++;                     
	      	if (responseCounter < responseData.length) {            
	      		loopResponses();             
	      	}                       
	}, 1750)
}
*/
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

//    loopEvents();  
//	loopAttacks();  
//	loopResponses();   
	
	displayData();
});
