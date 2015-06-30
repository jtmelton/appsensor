var socket;
var client;

function subscribeOnSuccess(frame) {
	  client.subscribe("/events", function(message) {
	    console.log("saw event: " + message);
	  });
	
	  client.subscribe("/attacks", function(message) {
		  console.log("saw event: " + message);
	  });
	  
	  client.subscribe("/responses", function(message) {
		  console.log("saw response: " + message);
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
		   $.get(apiBaseUrl + '/dashboard/ping');
		}
	, 840000); 
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
    {
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
    }
];

var attackData = [
    {
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
    }
];

var responseData = [
    {
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
    }
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

function addActivityMessage(element) {
	var tableRef = document.getElementById('activity_log');
	
	//delete last row if table too big
	if(tableRef.rows.length > 10) {
		tableRef.deleteRow(tableRef.rows.length -1)
	}
	
	//console.log('num rows = ' + tableRef.rows.length);
	
	var newRow = tableRef.insertRow(0);
	
	var cType = newRow.insertCell(0);
	var txtType = document.createTextNode('a');
	cType.appendChild(txtType);
	
	var cDetPt = newRow.insertCell(1);
	var txtDetPt = document.createTextNode('b');
	cDetPt.appendChild(txtDetPt);
	
	var cUser = newRow.insertCell(2);
	var txtUser = document.createTextNode('c' + '(' + 'd' + ')');
	cUser.appendChild(txtUser);
	
	var cDash = newRow.insertCell(3);
	var txtDash = document.createTextNode(' --> ');
	cDash.appendChild(txtDash);
	
	var cDetSys = newRow.insertCell(4);
	var txtDetSys = document.createTextNode('e' + '(' + 'f' + ')');
	cDetSys.appendChild(txtDetSys);
	
	var cTS = newRow.insertCell(5);
	var txtTS = document.createTextNode('g');
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

function goFullScreen() {
	$("#appsensor-navbar").hide();
	$("#geo_full_screen").hide();
	$("#geo_normal_screen").show();
	console.log('detached1 is ' + detached);
}

function goNormalScreen() {
	$("#appsensor-navbar").show();
	$("#geo_normal_screen").hide();
	$("#geo_full_screen").show();
}

//= $('#element').detach();
//$('body').append(detached);
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

    loopEvents();  
	loopAttacks();  
	loopResponses();   
	
	displayData();
});
