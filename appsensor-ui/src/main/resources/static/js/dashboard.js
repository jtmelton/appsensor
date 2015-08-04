var socket;
var client;

function addActivityMessage(element) {
	var tableRef = document.getElementById('dashboard-activity-log');
	
	//delete last row if table too big
	if(tableRef.rows.length > 10) {
		tableRef.deleteRow(tableRef.rows.length -1)
	}
	
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

function activateSlider(selectedTimeSpan) {
	var items =[ 'Month','Week','Day','Shift', 'Hour'];
	var s = $("#timeline-slider");

	s.slider({
	  min:1,
	  max:items.length,
	  slide: function( event, ui ) {
		  var selectedTimeSpan = items[ui.value - 1].toUpperCase();
		  console.log('user selected new timespan: "' + selectedTimeSpan + '"');
		  
		  console.log('refreshed data from slider change at ' + getTimestamp(selectedTimeSpan));
		  
		  initReact(selectedTimeSpan);
      }
	});

	var oneBig = 100 / (items.length - 1);

	$.each(items, function(key,value){
	  var w = oneBig;
	  if(key === 0 || key === items.length-1)
	    w = oneBig/2;
	    
	  $("#timeline-legend").append("<label id='"+value+"-slider-label' style='width: "+w+"%'>"+value+"</label>");
	});
	
	if (selectedTimeSpan) {
		s.slider('value', toCardinal(selectedTimeSpan));
	}
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

function capitalizeFirstLetter(s) {
    return s.charAt(0).toUpperCase() + s.slice(1);
}

function findCount(timeUnit, category, trendItemArray) {
	for (var i in trendItemArray) {
		if (trendItemArray[i].unit === timeUnit && trendItemArray[i].type === category) {
			return trendItemArray[i].count;
		}
	}
	
	return -1;
}

function updateSlider(data) {
  	var monthEvents = findCount('MONTH', 'EVENT', data);
  	var monthResponses = findCount('MONTH', 'RESPONSE', data);
  	var weekEvents = findCount('WEEK', 'EVENT', data);
  	var weekResponses = findCount('WEEK', 'RESPONSE', data);
  	var dayEvents = findCount('DAY', 'EVENT', data);
  	var dayResponses = findCount('DAY', 'RESPONSE', data);
  	var shiftEvents = findCount('SHIFT', 'EVENT', data);
  	var shiftResponses = findCount('SHIFT', 'RESPONSE', data);
  	var hourEvents = findCount('HOUR', 'EVENT', data);
  	var hourResponses = findCount('HOUR', 'RESPONSE', data);
  	
	$("#Month-slider-label").html('Month <span class="badge" title="' 
			+ monthEvents + ' events / ' + monthResponses + ' responses">' + monthEvents + ' / ' + monthResponses + '</span>');
	$("#Week-slider-label").html('Week <span class="badge" title="' 
			+ weekEvents + ' events / ' + weekResponses + ' responses">' + weekEvents + ' / ' + weekResponses + '</span>');
	$("#Day-slider-label").html('Day <span class="badge" title="' 
			+ dayEvents + ' events / ' + dayResponses + ' responses">' + dayEvents + ' / ' + dayResponses + '</span>');
	$("#Shift-slider-label").html('Shift <span class="badge" title="' 
			+ shiftEvents + ' events / ' + shiftResponses + ' responses">' + shiftEvents + ' / ' + shiftResponses + '</span>');
	$("#Hour-slider-label").html('Hour <span class="badge" title="' 
			+ hourEvents + ' events / ' + hourResponses + ' responses">' + hourEvents + ' / ' + hourResponses + '</span>');
}

function displayMorris(viewObject) {
	  //clean up contents and start over
  	  $("#category-count-graph").empty();
	  
      var viewData = JSON.parse(viewObject.data);
      var viewXKey = viewObject.xkey;
      var viewYKeys = viewObject.ykeys;
      var viewLabels = viewObject.labels;

      Morris.Area({
    	  element: 'category-count-graph',
    	  data: JSON.parse(viewObject.data),
    	  xkey: viewObject.xkey,
    	  ykeys: viewObject.ykeys,
    	  labels: viewObject.labels
    	});
}

var Dashboard = React.createClass({
	  loadDashboardObjectFromServer: function() {
		  
		  var selectedTimeSpan = this.props.selectedTimeSpan;
		  	
		  	var timestamp = getTimestamp(selectedTimeSpan);
		  
		    $.ajax({
		      url: apiBaseUrl + '/api/dashboard/all?earliest=' + timestamp + '&limit=5&slices=10',
		      success: function(data) {
		    	this.setState({data: data});
		        
		    	console.log('pulled data back and refreshed ui at ' + timestamp);
		        
		        displayMorris(data.groupedEvents);
		        updateSlider(data.byTimeFrame);
		        
		      }.bind(this),
		      error: function(xhr, status, err) {
		        console.error(apiBaseUrl + '/api/dashboard/all?earliest=' + timestamp + '&limit=5&slices=10', status, err.toString());
		      }.bind(this)
		    });
	  },
	  
	  getInitialState: function() {
	    return {data: {}};
	  },
	  componentDidMount: function() {

		  var selectedTimeSpan = this.props.selectedTimeSpan;
		
		  activateSlider(selectedTimeSpan);
	    
		  this.loadDashboardObjectFromServer();
		  
		  var intervalVar = setInterval(this.loadDashboardObjectFromServer, 60 * 1000);	// refresh once per minute
		  setIntervals.push(intervalVar);
	  },
	  
	  render: function() {
		var timestamp = getTimestamp(this.props.selectedTimeSpan);
		
	    return (
			<div class="row">
			
			  <Slider data={this.state.data.byTimeFrame} />
			  
			  <br /><br />
			   
			  <div className="col-md-8">
				  <ByCategoryAccordion byCategory={this.state.data.byCategory} />
				  <ByCategoryCount />
			  </div>
			  
			  <div className="col-md-4">
			  	  	<LastUpdated timestamp={timestamp} />
					<br />
					<TopDetectionPoints topDetectionPoints={this.state.data.topDetectionPoints} />
					<TopUsers topUsers={this.state.data.topUsers} />
					<ActiveResponses activeResponses={this.state.data.activeResponses} />
			  </div>
			  
	      </div>
	    );
	  }
	});

var Slider = React.createClass({
	  render: function() {
		var data = this.props.data;
		
	    return (
	    	<div>
		    	<div id="timeline-legend"></div>
		    	<div id="timeline-slider"></div>
	    	</div>
	    );
	  }
	});

var ByCategoryAccordion = React.createClass({
	  render: function() {
		var byCategory = this.props.byCategory;
		
		var shouldRender = (!byCategory || byCategory.length === 0) ? "There are no categories found to be active in this time period." : <ByCategoryAccordionContent byCategory={byCategory}/>;
		
	    return (
    		<div>
		    	<h4 className="dashboard-section-header"><strong>Detection Point Categories</strong></h4>
	    		{shouldRender}
    		</div>
	    );
	  }
	});

var ByCategoryAccordionContent = React.createClass({
	  render: function() {
		  var byCategory = this.props.byCategory;
		
		  var content = '';
		  
		  for (index in byCategory) {
			  var categoryData = byCategory[index];
			  var categoryName = categoryData.category;
			  var categoryNameNoWhitespace = categoryName.replace(/ /g,'');
			  
			  var eventCount = categoryData.eventCount;
			  var attackCount = categoryData.attackCount;
			  var recentEvents = categoryData.recentEvents;
			  var recentAttacks = categoryData.recentAttacks;
			 
			  var countByLabel = JSON.parse(categoryData.countByLabel);
			  
			  var panelContent = 
				  '<div class="row">' + 
	    		  '	 <div class="col-md-8">' + 
	    		  '	  	<h4 class="dashboard-section-header"><strong>Recent Events</strong></h4>' +
	    		  '		<div class="table-responsive">' +
			      '		  <table class="table table-hover table-bordered">' +
			      '     	<thead>' +
				  '  		    <tr>' +
				  '  		    	<th>Label</th>' +
				  '  		    	<th>User</th>' +
				  '  		    	<th>Detection System</th>' +
				  '  		    	<th>Timestamp</th>' +
				  '  		    </tr>' +
				  '  		</thead>' +
				  '  		<tbody>';
	
			  if( $.isEmptyObject(recentEvents) ) {
				  panelContent += '<tr><td colspan="4">There are no events found to be active in this time period.</td></tr>';
	    	  } else {
	    		  for (var index in recentEvents) {
	    			  var event = recentEvents[index];
	
	    			  var label = '<a href="' + apiBaseUrl + '/detection-points/' + event.detectionPoint.label + '">' + event.detectionPoint.label + '</a>'
	    			  var user = '<a href="' + apiBaseUrl + '/users/' + event.user.username + '">' + event.user.username + '</a>';
	    			  var detectionSystem = event.detectionSystem.detectionSystemId;
	    			  var timestamp = event.timestamp;
	    			  
	    			  panelContent += '<tr><td>' + label + '</td><td>' + user + '</td><td>' + detectionSystem + '</td><td>' + timestamp + '</td></tr>';
	    		  }
	    	  }
	    		  
			  panelContent +=
				  '  	   </tbody>' +
				  '	     </table>' +
				  '    </div>' +
				  '	  	<h4 class="dashboard-section-header"><strong>Recent Attacks</strong></h4>' +
	    		  '		<div class="table-responsive">' +
			      '		  <table class="table table-hover table-bordered">' +
			      '     	<thead>' +
				  '  		    <tr>' +
				  '  		    	<th>Label</th>' +
				  '  		    	<th>From</th>' +
				  '  		    	<th>To</th>' +
				  '  		    	<th>Timestamp</th>' +
				  '  		    </tr>' +
				  '  		</thead>' +
				  '  		<tbody>';
	
			  if( $.isEmptyObject(recentAttacks) ) {
				  panelContent += '<tr><td colspan="4">There are no attacks found to be active in this time period.</td></tr>';
	    	  } else {
	    		  for (var index in recentAttacks) {
	    			  var attack = recentAttacks[index];
	
	    			  var label = '<a href="' + apiBaseUrl + '/detection-points/' + attack.detectionPoint.label + '">' + attack.detectionPoint.label + '</a>'
	    			  var user = '<a href="' + apiBaseUrl + '/users/' + attack.user.username + '">' + attack.user.username + '</a>';
	    			  var detectionSystem = attack.detectionSystem.detectionSystemId;
	    			  var timestamp = attack.timestamp;
	    			  
	    			  panelContent += '<tr><td>' + label + '</td><td>' + user + '</td><td>' + detectionSystem + '</td><td>' + timestamp + '</td></tr>';
	    		  }
	    	  }
	    		  
			  panelContent +=
				  '  	   </tbody>' +
				  '	     </table>' +
				  '    </div>' +
				  '  </div>' +
	    		  '  <div class="col-md-4">' +
		    	  '	  	<h4 class="dashboard-section-header"><strong>Events By Detection Point</strong></h4>' +
	    		  '		<div class="table-responsive">' +
			      '		  <table class="table table-hover table-bordered">' +
			      '     	<thead>' +
				  '  		    <tr>' +
				  '  		    	<th>Label</th>' +
				  '  		    	<th>#</th>' +
				  '  		    </tr>' +
				  '  		</thead>' +
				  '  		<tbody>';
	
			  if( $.isEmptyObject(countByLabel) || $.isEmptyObject(countByLabel.backingMap) ) {
				  panelContent += '<tr><td colspan="2">There are no detection points found to be active in this time period.</td></tr>';
	    	  } else {
	    		  for (var detectionPointLabel in countByLabel.backingMap) {
	    			  var eventAttackMap = countByLabel.backingMap[detectionPointLabel];
	    			  var count = (eventAttackMap.EVENT) ? eventAttackMap.EVENT : 0;
	    			  panelContent += '<tr><td>' + detectionPointLabel + '</td><td>' + count + '</td></tr>';
	    		  }
	    	  }
			  
			  panelContent +=
				  '  		</tbody>' +
				  '		  </table>' +
			      '		</div>' +
			      '		<h4 class="dashboard-section-header"><strong>Attacks By Detection Point</strong></h4>' +
	    		  '		<div class="table-responsive">' +
			      '		  <table class="table table-hover table-bordered">' +
			      '		  	<thead>' +
				  '  		    <tr>' +
				  '  		    	<th>Label</th>' +
				  '  		    	<th>#</th>' +
				  '  		    </tr>' +
				  '  		</thead>' +
				  '  		<tbody>';
	
	    		  if( $.isEmptyObject(countByLabel) || $.isEmptyObject(countByLabel.backingMap) ) {
	    			  panelContent += '<tr><td colspan="2">There are no detection points found to be active in this time period.</td></tr>';
		    	  } else {
		    		  for (var detectionPointLabel in countByLabel.backingMap) {
		    			  var eventAttackMap = countByLabel.backingMap[detectionPointLabel];
		    			  var count = (eventAttackMap.ATTACK) ? eventAttackMap.ATTACK : 0;
		    			  panelContent += '<tr><td>' + detectionPointLabel + '</td><td>' + count + '</td></tr>';
		    		  }
		    	  }
				  
			  panelContent +=
				  '  		</tbody>' +
				  '		  </table>' +
			      '		</div>' +
	    		  '  </div>' + 
	    		  '</div>';
			  
			  content += 
				  '<div class="panel panel-default">' +
				  '  <div class="panel-heading" role="tab" id="heading' + categoryNameNoWhitespace + '">' +
				  '  <h2>' +
				  '    	<span class="glyphicon glyphicon-tasks" aria-hidden="true"></span>&nbsp;&nbsp;' +
				  '      <a class="collapsed" role="button" data-toggle="collapse" data-parent="#category-accordion" href="#collapse' + categoryNameNoWhitespace + '" aria-expanded="false" aria-controls="collapse' + categoryNameNoWhitespace + '">' +
				  '       ' + categoryName +
				  '      </a>' +
				  '      &nbsp;<span class="badge" title="' + eventCount + ' events / ' + attackCount + ' attacks">' + eventCount + ' / ' + attackCount + '</span>' +
				  '    </h2>' +
				  '  </div>' +
				  '  <div id="collapse' + categoryNameNoWhitespace + '" class="panel-collapse collapse" role="tabpanel" aria-labelledby="heading' + categoryNameNoWhitespace + '">' +
				  '    <div class="panel-body">' +
				  '     ' + panelContent + 
				  '    </div>' +
				  '  </div>' +
				  '</div>';
		  }

	    return (
	    		<AccordionContent content={content} />
	    );
	  }
	});

var ByCategoryCount = React.createClass({
	  render: function() {
		return (
    		<div>
    		<h4 className="dashboard-section-header"><strong>Count By Categories</strong></h4>
    		<div id='category-count-graph'>
			</div>
			</div>
	    );
	  }
	});

var LastUpdated = React.createClass({
	  render: function() {
		var timestamp = this.props.timestamp;
		
	    return (
	    	<div className="text-right"><span>Last Refresh: </span><span id="last-updated-time">{timestamp}</span></div>
	    );
	  }
	});

var TopDetectionPoints = React.createClass({
	  render: function() {
		var topDetectionPoints = this.props.topDetectionPoints;
		
		var shouldRender = ( $.isEmptyObject(topDetectionPoints) ) ? 
				<EmptyTable header="Most Active Detection Points" message="There are no detection points found to be active in this time period." />: 
					<TopDetectionPointsContent topDetectionPoints={topDetectionPoints} />;
		
	    return (
	    		<div>
	    			{shouldRender}
	    		</div>
	    );
	    
	  }
	});

var TopDetectionPointsContent = React.createClass({
	  render: function() {
		var topDetectionPoints = this.props.topDetectionPoints;
		
		var rows = [];

		for (key in topDetectionPoints) {
			var detectionPoint = JSON.parse(key);
			var content = '<a href="'
				  + apiBaseUrl + '/detection-points/' + detectionPoint.label + '">' + detectionPoint.label + '</a>' 
				  + ' (' + detectionPoint.category + ')' 
				  + ' (' + topDetectionPoints[key] + ' events)';
			rows.push(<SingleColumnRow message={content} />);
		}
		
	    return (
    		<div className="table-responsive">
		    	<table className="table table-hover table-bordered">
				    <tr>
				    	<th className="dashboard-section-header">Most Active Detection Points</th>
				    </tr>
				    {rows}
				</table>
			</div>
	    );
	  }
	});

var TopUsers = React.createClass({
	  render: function() {
		  var topUsers = this.props.topUsers;
		  
		  var shouldRender = ( $.isEmptyObject(topUsers) ) ? 
					<EmptyTable header="Most Active Users" message="There are no users found to be active in this time period." />: 
						<TopUsersContent topUsers={topUsers} />;
			
		    return (
		    		<div>
		    			{shouldRender}
		    		</div>
		    );
	  }
	});

var TopUsersContent = React.createClass({
	  render: function() {
		var topUsers = this.props.topUsers;
		
		var rows = [];

		for (key in topUsers) {
			var content = '<a href="'
				  + apiBaseUrl + '/users/' + key + '">' + key + '</a>' 
				  + ' (' + topUsers[key] + ' events)';
			
			rows.push(<SingleColumnRow message={content} />);
		}
		
	    return (
	    	<div className="table-responsive">
		    	<table className="table table-hover table-bordered">
				    <tr>
				    	<th className="dashboard-section-header">Most Active Users</th>
				    </tr>
				    {rows}
				</table>
			</div>
	    );
	  }
	});

			
var ActiveResponses = React.createClass({
	  render: function() {
		var activeResponses = this.props.activeResponses;
		
		var shouldRender = ( $.isEmptyObject(activeResponses) ) ? 
				<EmptyTable header="Active Responses" message="There are no responses found to be active in this time period." />: 
					<ActiveResponsesContent activeResponses={activeResponses} />;
		
	    return (
	    		<div>
	    			{shouldRender}
	    		</div>
	    );
	  }
	});

var ActiveResponsesContent = React.createClass({
	  render: function() {
		var activeResponses = this.props.activeResponses;
		
		var rows = [];

		for (index in activeResponses) {
			var response = activeResponses[index];
			
			var duration = (response.interval.duration && response.interval.unit) ? 
					' (' + response.interval.duration + ' ' + response.interval.unit + ')' : 
						'';
			
			var content = response.action
				  + ' ' + duration
				  + ' (<a href="' + apiBaseUrl + '/users/' + response.user.username + '">' + response.user.username + '</a>' + ')'
				  + ' (client app: "' + response.detectionSystem.detectionSystemId + '")'
				  + ' (started at: "' + moment(response.timestamp).format("YYYY/MM/DD, HH:mm:ss") + '")';

			rows.push(<SingleColumnRow message={content} />);
		}
		
	    return (
	    	<div className="table-responsive">
		    	<table className="table table-hover table-bordered">
				    <tr>
				    	<th className="dashboard-section-header">Active Responses</th>
				    </tr>
				    {rows}
				</table>
			</div>
	    );
	  }
	});

var SingleColumnRow = React.createClass({
	  render: function() {
		var message = this.props.message;
		
	    return (
	    		<tr><td dangerouslySetInnerHTML={{__html: message}} /></tr>
	    );
	  }
	});

var AccordionContent = React.createClass({
	  render: function() {
		var content = this.props.content;
		
	    return (
	    	<div className="panel-group" id="category-accordion" role="tablist" aria-multiselectable="true" dangerouslySetInnerHTML={{__html: content}} />
	    );
	  }
	});

var EmptyTable = React.createClass({
	  render: function() {
		var header = this.props.header;
		var message = this.props.message;
		
	    return (
	    	<div className="table-responsive">
		    	<table className="table table-hover table-bordered">
				    <tr>
				    	<th className="dashboard-section-header">{header}</th>
				    </tr>
				    <tr>
				    	<td>{message}</td>
				    </tr>
				</table>
			</div>
	    );
	  }
	});

var setIntervals = [];

function initReact(selectedTimeSpan) {
	
	// remove any previous reset intervals
	$.each( setIntervals, function( i, val ) {
		  clearInterval(val);
		  var index = setIntervals.indexOf(val);
		  if (index > -1) {
			  setIntervals.splice(index, 1);
		  }
		});
	
	React.unmountComponentAtNode(document.getElementById('react_dashboard_container'));
	React.render(<Dashboard selectedTimeSpan={selectedTimeSpan} />, document.getElementById('react_dashboard_container'));
}

$(function() {
	stompConnect();
	keepalive();
	
	// on first load of the page, find the shortest time frame that has events and load it, defaulting to month if none are found
	$.ajax({
	      url: apiBaseUrl + '/api/dashboard/by-time-frame',
	      
	      success: function(data) {

	    		var span;
	    		
	    	  	var monthEvents = findCount('MONTH', 'EVENT', data);
	    	  	var weekEvents = findCount('WEEK', 'EVENT', data);
	    	  	var dayEvents = findCount('DAY', 'EVENT', data);
	    	  	var shiftEvents = findCount('SHIFT', 'EVENT', data);
	    	  	var hourEvents = findCount('HOUR', 'EVENT', data);
	    	  	
	    	  	if (hourEvents > 0) {
	    	  		span = 'HOUR';
	    	  	} else if (shiftEvents > 0) {
	    	  		span = 'SHIFT';
	    	  	} else if (dayEvents > 0) {
	    	  		span = 'DAY';
	    	  	} else if (weekEvents > 0) {
	    	  		span = 'WEEK';
	    	  	} else {
	    	  		span = 'MONTH';
	    	  	}
	    	  	
		  		initReact(span);
	      },
	      error: function(data) {
	    	  console.log('Failure contacting appsensor service for loading updateSlider.');
	      }
	  });
	
});