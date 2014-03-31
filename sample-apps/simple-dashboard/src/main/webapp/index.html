<!DOCTYPE html>
<html>
    <head>
        <title>AppSensor Dashboard</title>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
        <style>
        	.wrapper {
        		width: 1400px;
        		text-align: center;
        		margin: 0 auto;
        	}
        	
            #eventcontainer {
                border: 1px green solid;
            }
            #attackcontainer {
                border: 1px blue solid;
            }
            #responsecontainer {
                border: 1px red solid;
            }
            
            .leftcontainer {
                float:left;
            }
            .middlecontainer {
                float:left;
            }
            .rightcontainer {
                float:right;
            }
            
            .shortcontainer {
           		overflow-y: auto; 
                padding: 10px;
                margin: 20px;
                width: 400px;
                //height:700px;
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
        
        <script src="//ajax.googleapis.com/ajax/libs/jquery/2.1.0/jquery.min.js"></script>
        
    </head>
    <body>
        <div class="wrapper">
        	<span id="refreshing_event_text" style="background-color: yellow"></span>&nbsp;&nbsp;
        	<span id="refreshing_attack_text" style="background-color: yellow"></span>&nbsp;&nbsp;
        	<span id="refreshing_response_text" style="background-color: yellow"></span>&nbsp;&nbsp;
        	<span id="refresh_status" style="background-color: yellow">Not Loading</span>&nbsp;&nbsp;
	        <h1>AppSensor Dashboard Example</h1>
	        <div>
	        	<input type="button" id="addBobRecordButton" name="addBobRecordButton" value="Add Data (Bob)"  />
	        	<input type="button" id="addOtherRecordButton" name="addOtherRecordButton" value="Add Data (Somebody Else)"  />
	        </div>
	        <div>
	        	<input type="button" id="startRefreshButton" name="startRefreshButton" value="Refresh"  />
	        	<input type="button" id="stopRefreshButton" name="stopRefreshButton" value="Stop Refresh"  />
	        </div>
	        <div class="leftcontainer shortcontainer">
	            Events<hr />
	        </div>
	        <div class="middlecontainer shortcontainer">
	            Attacks<hr />
	        </div>
	        <div class="rightcontainer shortcontainer">
	            Responses<hr />
	        </div>
        </div>
        <div class="wrapper">
	        <div id="eventcontainer" class="leftcontainer container">
	        </div>
	        <div id="attackcontainer" class="middlecontainer container">
	        </div>
	        <div id="responsecontainer" class="rightcontainer container">
	        </div>
        </div>
    </body>
    
    <script type="text/javascript">
        
    		var five_minutes = 1000 * 60 * 5;	// ms * s * m
    		var latest_time = Date.now() - five_minutes;
    		
    		var should_run = true;
    		
	        function addRecord(name){
	        	var jsonStr = '{"user":{"username":"' + name + '"},"detectionPoint":{"id":"IE1"},"timestamp":' + Date.now() + '}';
	        	
	            $.ajax({
	            	type: "POST",
	                url: apiUrl + "/events",
	                data: jsonStr,
	                headers: { 'X-Appsensor-Client-Application-Name2': 'myclientapp' },
	                contentType:"application/json; charset=utf-8",
	                success:function(result){
	                	//$("#mytext").val('added data for : ' + name);
	                },
		            error:function(result){
		            	console.log('had an error: ' + JSON.stringify(result));
	                }
	            }); 
	        }
	        
	        function refreshData(){
	            if (should_run) {
	            	$("#refreshing_event_text").html('loading events');
	            	$("#refreshing_attack_text").html('loading attacks');
	            	$("#refreshing_response_text").html('loading responses');
	            	
	            	$.ajax({
		                url: apiUrl + "/reports/events?earliest=" + latest_time,
		                headers: { 'X-Appsensor-Client-Application-Name2': 'myclientapp' },
		                success:function(result){
		                	displayResults(result, 'event');
		                	$("#refreshing_event_text").html('');
		                },
			            error:function(result){
			            	console.log('had an error: ' + JSON.stringify(result));
		                }
		            }); 
		        	
		            $.ajax({
		                url: apiUrl + "/reports/attacks?earliest=" + latest_time,
		                headers: { 'X-Appsensor-Client-Application-Name2': 'myclientapp' },
		                success:function(result){
		                	displayResults(result, 'attack');
		                	$("#refreshing_attack_text").html('');
		                },
			            error:function(result){
			            	console.log('had an error: ' + JSON.stringify(result));
		                }
		            }); 
		            
		            $.ajax({
		                url: apiUrl + "/reports/responses?earliest=" + latest_time,
		                headers: { 'X-Appsensor-Client-Application-Name2': 'myclientapp' },
		                success:function(result){
		                	displayResults(result, 'response');
		                	$("#refreshing_response_text").html('');
		                },
			            error:function(result){
			            	console.log('had an error: ' + JSON.stringify(result));
		                }
		            }); 
		            
		            //update latest time
		            latest_time = Date.now();
		            
		            setTimeout(refreshData, 5000);
	            }
	        }
	        
	        function startRefresh(){
	        	 $("#refresh_status").html('Loading');
	        	should_run = true;
	        }
	        
	        function stopRefresh(){
	        	$("#refresh_status").html('Not Loading');
	        	should_run = false;
	        }
	        
	        var apiUrl = "http://localhost:8080/sample-appsensor-ws-rest-server/api/v1.0";
	        
	        $("#addBobRecordButton").click(function() {addRecord('bob');});
	       	$("#addOtherRecordButton").click(function() {addRecord('somebody_else');});
	       	$("#startRefreshButton").click(function() {startRefresh(); refreshData();}); 
	       	$("#stopRefreshButton").click(function() {stopRefresh();}); 
	        
	       	function displayResults(objArray, dataType) {
                for (var i = 0; i < objArray.length; i++) {
                	var as = objArray[i];

                    var p = document.createElement("p");
                	p.setAttribute("class", "server");
                	
                    switch (dataType) {
    				    case "event":
    				        p.innerHTML = "Event triggered for detection point [" + as.detectionPoint.id + "] " +
    				        	"by user [" + as.user.username + "] at [" + toDateString(as.timestamp) + "] " + 
    				        	"on system [" + as.detectionSystemId + "]";
    				        break;
    				    case "attack":
    				    	p.innerHTML = "Attack triggered for detection point [" + as.detectionPoint.id + "] " +
    			        		"by user [" + as.user.username + "] at [" + toDateString(as.timestamp) + "] " + 
    				        	"on system [" + as.detectionSystemId + "]";
    				        break;
    				    case "response":
    				    	p.innerHTML = "Response triggered " +
    			        		"by user [" + as.user.username + "] at [" + toDateString(as.timestamp) + "] " + 
    				        	"on system [" + as.detectionSystemId + "] and the response action is [" + as.action + "]";
    				        break;
    				}
                    
                    var container = document.getElementById(dataType + "container");
                    //container.appendChild(p);
                    container.insertBefore(p, container.firstChild);
                    
                }
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
</html>