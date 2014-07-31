<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
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
	        	User:  <input id="entered_user" type="text" placeholder="Enter the username to associate to the event" /><br />
	        	
	        	Event: 
	        	 <select id="selected_detection_point">
	        	 	<c:forEach var="configuredDetectionPoint" items="${configuredDetectionPoints}">
			   			<option value="<c:out value="${configuredDetectionPoint.label}"/>:<c:out value="${configuredDetectionPoint.category}"/>"><c:out value="${configuredDetectionPoint.category}"/> : <c:out value="${configuredDetectionPoint.label}"/></option>
			   		</c:forEach>
		        </select>
	        	<br /><br />
	        	
	        	<input type="button" id="addRecordButton" name="addRecordButton" value="Add Data"  />
	        	<br />
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

    		function addRecord(){
	        	var dateStr = ISODateString(new Date());
	        	var nameStr = $("#entered_user").val();
	        	var detectionPoint = $("#selected_detection_point").val();
	        	var labelStr = detectionPoint.split(':')[0];
	        	var categoryStr = detectionPoint.split(':')[1];
	        	var detectionPointStr = '{"label":"' + labelStr + '", "category":"' + categoryStr + '"}';
	        	
	        	var jsonStr = '{"user":{"username":"' + nameStr + '"},"detectionPoint":' + detectionPointStr + ',"timestamp":"' + dateStr + '"}';
	        	
	            $.ajax({
	            	type: "POST",
	                url: apiUrl + "/events",
	                data: jsonStr,
	                headers: { 'X-Appsensor-Client-Application-Name2': 'myclientapp' },
	                contentType:"application/json; charset=utf-8",
	                success:function(result){
	                	$("#results").text('Added [' + categoryStr + '(' + labelStr + ')] event for [' + nameStr + '] at [' + dateStr + ']');
	                },
		            error:function(result){
		            	$("#results").text('had an error : ' + JSON.stringify(result));
		            	console.log('had an error: ' + JSON.stringify(result));
	                }
	            });
	        }
	        
	        var apiUrl = $(location).attr('protocol') + "//" + $(location).attr('host') + "/sample-appsensor-ws-rest-server/api/v1.0";
			
	        $("#addRecordButton").click(function() {addRecord();});
	        
        </script>
</html>