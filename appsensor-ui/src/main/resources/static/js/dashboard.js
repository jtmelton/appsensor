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
