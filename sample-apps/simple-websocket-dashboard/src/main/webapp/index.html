<!DOCTYPE html>
<html>
    <head>
        <title>AppSensor Dashboard (WebSocket)</title>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
        <style>
        	#wrapper {
        		width: 1400px;
        		text-align: center;
        		margin: 0 auto;
        	}
        	
            #eventcontainer {
                border: 1px green solid;
                float:left;
            }
            #attackcontainer {
                border: 1px blue solid;
                float:left;
            }
            #responsecontainer {
                border: 1px red solid;
                float:right;
            }
            .container {
           		overflow-y: auto; 
                padding: 10px;
                margin: 20px;
                width: 400px;
                height:700px;
            }
            
            p.client {
                border-bottom: 1px aquamarine solid;
            }
            p.server {
                border-bottom: 1px crimson solid;
            }
            input {
                padding: 5px;
                width: 250px;
            }
            button {
                padding: 5px;
            }
        </style>
        
        
        <script>
        	var url = "ws://localhost:8080/simple-websocket-dashboard/dashboard";
            var dashboard = null;// new WebSocket();
            
            if ('WebSocket' in window) {
            	dashboard = new WebSocket(url);
            } else if ('MozWebSocket' in window) {
            	dashboard = new MozWebSocket(url);
            } else {
                alert('WebSocket is not supported by this browser.');
                //return;
            }
            dashboard.onopen = function () {
                console.log('Info: WebSocket connection opened.');
            };
            dashboard.onclose = function () {
                console.log('Info: WebSocket connection closed.');
            };
            
            dashboard.onmessage = function(evt) {
            	console.log('Received: ' + evt.data);
                var p = document.createElement("p");
                p.setAttribute("class", "server");
                
                var json = evt.data;
                var obj = JSON.parse(json);
				var eventType = obj.dataType;
                var as = obj.dataValue;

                switch (eventType) {
				    case "event":
				        p.innerHTML = "Event triggered for detection point [" + as.detectionPoint.id + "] " +
				        	"by user [" + as.user.username + "] at [" + toDateString(as.timestamp) + "] " + 
				        	"on system [" + as.detectionSystemId + "] and is of type [" + as.eventType + "]";
				        break;
				    case "attack":
				    	p.innerHTML = "Attack triggered for detection point [" + as.detectionPoint.id + "] " +
			        		"by user [" + as.user.username + "] at [" + toDateString(as.timestamp) + "] " + 
				        	"on system [" + as.detectionSystemId + "]";
				        break;
				    case "response":
				    	p.innerHTML = "Response triggered for detection point [" + as.detectionPoint.id + "] " +
			        		"by user [" + as.user.username + "] at [" + toDateString(as.timestamp) + "] " + 
				        	"on system [" + as.detectionSystemId + "] and the response action is [" + as.action + "]";
				        break;
				}
                var container = document.getElementById(eventType + "container");
                container.appendChild(p);
            };
            
            function toDateString(unix_timestamp) {
            	var date = new Date(unix_timestamp);
            	
            	var hour = date.getHours();
            	var minute = date.getMinutes();
            	var second = date.getSeconds();
            	var day_of_month = date.getDate();
                var month = date.getMonth() + 1;
                var year = date.getFullYear();
                
                return year + '-' + preZero(month) + '-' + preZero(day_of_month) + ' ' + preZero(hour) + ':' + preZero(minute) + ':' + preZero(second);
            }
            
            function preZero(value) {
            	return (value <= 9) ? '0' + value : value;
            }
        </script>
    </head>
    <body>
        <div id="wrapper">
	        <h1>AppSensor Dashboard WebSocket Example</h1>
	        <h4>Run the <em style="color: red">DemoDataPopulator</em> class in the <em style="color: red">appsensor-reporting-websocket</em> project to see data on this page.</h4>
	        <div id="eventcontainer" class="container">
	            Events<hr />
	        </div>
	        <div id="attackcontainer" class="container">
	            Attacks<hr />
	        </div>
	        <div id="responsecontainer" class="container">
	            Responses<hr />
	        </div>
        </div>
    </body>
</html>