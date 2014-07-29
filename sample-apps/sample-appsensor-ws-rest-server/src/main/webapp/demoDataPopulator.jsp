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
	        <h1>AppSensor Data Input For Dashboard</h1>
	        <div>
	        	<input type="button" id="addBobRecordButton" name="addBobRecordButton" value="Add Data (Bob)"  />
	        	<input type="button" id="addOtherRecordButton" name="addOtherRecordButton" value="Add Data (Somebody Else)"  />
	        </div>
	        <div>
	        	<br />
	        	<span style="background-color: yellow" id="results">No data saved yet.</span>
	        </div>
        </div>
    </body>
    
    <script type="text/javascript">
        
    		function ISODateString(d){
				
    			function pad(n){return n<10 ? '0'+n : n;}
				
			 	return d.getUTCFullYear()+'-'
				      + pad(d.getUTCMonth()+1)+'-'
				      + pad(d.getUTCDate())+'T'
				      + pad(d.getUTCHours())+':'
				      + pad(d.getUTCMinutes())+':'
				      + pad(d.getUTCSeconds())+'Z';
			}
			
	        function addRecord(name){
	        	//TODO: change this so we can make it different labels and categories
	        	var dateStr = ISODateString(new Date());
	        	var jsonStr = '{"user":{"username":"' + name + '"},"detectionPoint":{"label":"IE1", "category":"Input Validation"},"timestamp":"' + dateStr + '"}';
	            $.ajax({
	            	type: "POST",
	                url: apiUrl + "/events",
	                data: jsonStr,
	                headers: { 'X-Appsensor-Client-Application-Name2': 'myclientapp' },
	                contentType:"application/json; charset=utf-8",
	                success:function(result){
	                	$("#results").text('added data for : ' + name + ' at ' + dateStr);
	                },
		            error:function(result){
		            	$("#results").text('had an error : ' + JSON.stringify(result));
		            	console.log('had an error: ' + JSON.stringify(result));
	                }
	            }); 
	        }
	        
	        //var apiUrl = $(location).attr('protocol') + "://" + $(location).attr('host') + "/sample-appsensor-ws-rest-server/api/v1.0";
	        var apiUrl = "http://localhost:8080/sample-appsensor-ws-rest-server/api/v1.0";
	        
	        $("#addBobRecordButton").click(function() {addRecord('bob');});
	       	$("#addOtherRecordButton").click(function() {addRecord('somebody_else');});
	        
        </script>
</html>