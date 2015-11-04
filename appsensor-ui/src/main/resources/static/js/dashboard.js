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
		      url: apiBaseUrl + '/api/dashboard/all?earliest=' + encodeURIComponent(timestamp) + '&limit=5&slices=10',
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

var RecentItemsPanel = React.createClass({
	  render: function() {
		var recentItems = this.props.recentItems;
		var type = this.props.type;
		
		var typeLabel = "";
		
		if ("EVENT" === type) {
			typeLabel = "events";
		} else if ("ATTACK" === type) {
			typeLabel = "attacks";
		} 
		
		var message = "There are no " + typeLabel + " found to be active in this time period.";
		
		var shouldRender = ( $.isEmptyObject(recentItems) ) ? 
				<tbody><ColspanRow colCount="4" message={message} /></tbody>: 
					<RecentItemsPanelContent recentItems={recentItems} />;
				
	    return (
			<span>{shouldRender}</span>
	    );
	  }
	});

var RecentItemsPanelContent = React.createClass({
	  render: function() {
		var recentItems = this.props.recentItems;
		
		var recentItemsRender = recentItems.map(function (item) {
			return (
		    	<tr>
		    	  <td><a href={[apiBaseUrl + '/detection-points/' + item.detectionPoint.label]}>{item.detectionPoint.label}</a></td>
		    	  <td><a href={[apiBaseUrl + '/users/' + item.user.username]}>{item.user.username}</a></td>
		    	  <td>{item.detectionSystem.detectionSystemId}</td>
		    	  <td>{item.timestamp}</td>
		    	</tr>
		      );
		    });
		
	    return (
	    	<tbody>
			    {recentItemsRender}
			</tbody>
	    );
	  }
	});

var ByDetectionPointPanel = React.createClass({
	  render: function() {
		var countByLabel = this.props.countByLabel;
		
		var shouldRender = ( $.isEmptyObject(countByLabel) || $.isEmptyObject(countByLabel.backingMap) ) ? 
				<tbody><ColspanRow colCount="2" message="There are no detection points found to be active in this time period." /></tbody>: 
					<ByDetectionPointPanel countByLabel={countByLabel} />;
				
	    return (
			<span>{shouldRender}</span>
	    );
	  }
	});

var ByDetectionPointPanel = React.createClass({
	  render: function() {
		var countByLabel = this.props.countByLabel;
		var type = this.props.type;
		
		var cblArray = [], item;

		for (key in countByLabel.backingMap) {
		    item = {};
		    item.label = key;
		    item.count = countByLabel.backingMap[key];
		    cblArray.push(item);
		}
		
		var byDetectionPointRender = cblArray.map(function (detectionPointInfo) {
			
			var count = 0;
			
			if ("EVENT" === type) {
				count = (detectionPointInfo.count.EVENT) ? detectionPointInfo.count.EVENT : 0;
			} else if ("ATTACK" === type) {
				count = (detectionPointInfo.count.ATTACK) ? detectionPointInfo.count.ATTACK : 0;
			}
			
			return (
		    	<tr>
		    	  <td>{detectionPointInfo.label}</td>
		    	  <td>{count}</td>
		    	</tr>
		      );
		    });
		
	    return (
	    	<tbody>
			    {byDetectionPointRender}
			</tbody>
	    );
	  }
	});

var AccordionPanelContent = React.createClass({
	  render: function() {
		var recentEvents = this.props.recentEvents;
		var recentAttacks = this.props.recentAttacks;
		var countByLabel = this.props.countByLabel;

	    return (
				  <div className="row"> 
	    		  	 <div className="col-md-8"> 
	    		  	  	<h4 className="dashboard-section-header"><strong>Recent Events</strong></h4>
	    		  		<div className="table-responsive">
			      		  <table className="table table-hover table-bordered">
			      		  	<thead>
				    		    <tr>
				    		    	<th>Label</th>
				    		    	<th>User</th>
				    		    	<th>Detection System</th>
				    		    	<th>Timestamp</th>
				    		    </tr>
				    		</thead>
				    		<RecentItemsPanel type="EVENT" recentItems={recentEvents} />
				  	     </table>
				      </div>
				      
				  	  	<h4 className="dashboard-section-header"><strong>Recent Attacks</strong></h4>
	    		  		<div className="table-responsive">
			      		  <table className="table table-hover table-bordered">
			      		  	<thead>
				    		    <tr>
				    		    	<th>Label</th>
				    		    	<th>From</th>
				    		    	<th>To</th>
				    		    	<th>Timestamp</th>
				    		    </tr>
				    		</thead>
				    		<RecentItemsPanel type="ATTACK" recentItems={recentAttacks} />
				  	     </table>
				      </div>
				    </div>
	    		    <div className="col-md-4">
		    	  	  	<h4 className="dashboard-section-header"><strong>Events By Detection Point</strong></h4>
	    		  		<div className="table-responsive">
			      		  <table className="table table-hover table-bordered">
			      		  	<thead>
				    		    <tr>
				    		    	<th>Label</th>
				    		    	<th>#</th>
				    		    </tr>
				    		</thead>
				    		<ByDetectionPointPanel type="EVENT" countByLabel={countByLabel} />
				  		  </table>
			      		</div>
			      		<h4 className="dashboard-section-header"><strong>Attacks By Detection Point</strong></h4>
	    		  		<div className="table-responsive">
			      		  <table className="table table-hover table-bordered">
			      		  	<thead>
				    		    <tr>
				    		    	<th>Label</th>
				    		    	<th>#</th>
				    		    </tr>
				    		</thead>
				    		<ByDetectionPointPanel type="ATTACK" countByLabel={countByLabel} />
				  		  </table>
			      		</div>
	    		    </div> 
	    		  </div>
	    );
	  }
	});

var ByCategoryAccordionContent = React.createClass({
	  render: function() {
		  var byCategory = this.props.byCategory;
		
		  var content = '';
		  
		  var categoryDataRender = byCategory.map(function (categoryData) {
			  var categoryName = categoryData.category;
			  var categoryNameNoWhitespace = categoryName.replace(/ /g,'');
			  
			  var eventCount = categoryData.eventCount;
			  var attackCount = categoryData.attackCount;
			  var recentEvents = categoryData.recentEvents;
			  var recentAttacks = categoryData.recentAttacks;
			 
			  var countByLabel = JSON.parse(categoryData.countByLabel);

			  var headingName = 'heading' + categoryNameNoWhitespace;
			  var collapseName = 'collapse' + categoryNameNoWhitespace;
			  var collapseAnchor = '#collapse' + categoryNameNoWhitespace;
			  var countTitle = eventCount + ' events / ' + attackCount + ' attacks';
			  
			  var recentEvents = categoryData.recentEvents;
			  var recentAttacks = categoryData.recentAttacks;
			  var countByLabel = JSON.parse(categoryData.countByLabel);
			  
		      return (
	    		  <div className="panel panel-default">
				    <div className="panel-heading" role="tab" id={headingName}>
				    <h2>
				      	<span className="glyphicon glyphicon-tasks" aria-hidden="true"></span>&nbsp;&nbsp;
				        <a className="collapsed" role="button" data-toggle="collapse" data-parent="#category-accordion" href={collapseAnchor} aria-expanded="false" aria-controls={collapseName}>
				         {categoryName}
				        </a>
				        &nbsp;<span className="badge" title={countTitle}>{eventCount} / {attackCount}</span>
				      </h2>
				    </div>
				    <div id={collapseName} className="panel-collapse collapse" role="tabpanel" aria-labelledby={headingName}>
				      <div className="panel-body">
				        <AccordionPanelContent recentEvents={recentEvents} recentAttacks={recentAttacks} countByLabel={countByLabel} /> 
				      </div>
				    </div>
				  </div>
		      );
		    });

	    return (
    		<div className="panel-group" id="category-accordion" role="tablist" aria-multiselectable="true">
    			{categoryDataRender}
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
		
		var tdpArray = [], item;

		for (key in topDetectionPoints) {
		    item = {};
		    item.info = JSON.parse(key);
		    item.count = topDetectionPoints[key];
		    tdpArray.push(item);
		}
		
		var topDetectionPointsRender = tdpArray.map(function (detectionPoint) {
			  var label = detectionPoint.info.label;
			  var category = detectionPoint.info.category;
			  var count = detectionPoint.count;
			  
		      return (
		    	<tr>
		    	  <td>
		    	  	<a href={[apiBaseUrl + '/detection-points/' + label]}>{label}</a> ({category}) ({count} events)
		    	  </td>
		    	</tr>
		      );
		    });
		
	    return (
    		<div className="table-responsive">
		    	<table className="table table-hover table-bordered">
				    <tr>
				    	<th className="dashboard-section-header">Most Active Detection Points</th>
				    </tr>
				    {topDetectionPointsRender}
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
		
		var usersArray = [], item;

		for (key in topUsers) {
		    item = {};
		    item.name = key;
		    item.count = topUsers[key];
		    usersArray.push(item);
		}
		
		var topUserRender = usersArray.map(function (topUser) {
		      return (
		    	<tr>
		    	  <td><a href={[apiBaseUrl + '/users/' + topUser.name]}>{topUser.name}</a>  ({topUser.count} events)</td>
		    	</tr>
		      );
		    });
		
	    return (
	    	<div className="table-responsive">
		    	<table className="table table-hover table-bordered">
				    <tr>
				    	<th className="dashboard-section-header">Most Active Users</th>
				    </tr>
				    {topUserRender}
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
		
		var activeResponseRender = activeResponses.map(function (response) {
			  
			 var duration = (response.interval.duration && response.interval.unit) ? 
						' (' + response.interval.duration + ' ' + response.interval.unit + ')' : 
							'';
			 
			 var ts = moment(response.timestamp).format("YYYY/MM/DD, HH:mm:ss");
			 
		      return (
		    	<tr>
		    	  <td>
		    	  	{response.action} {duration} (<a href={[apiBaseUrl + '/users/' + response.user.username]}>{response.user.username}</a>)
		    	    (client app: "{response.detectionSystem.detectionSystemId}")
		    	    (started at: "{ts}")
		    	  </td>
		    	</tr>
		      );
		    });
		
		
	    return (
	    	<div className="table-responsive">
		    	<table className="table table-hover table-bordered">
				    <tr>
				    	<th className="dashboard-section-header">Active Responses</th>
				    </tr>
				    {activeResponseRender}
				</table>
			</div>
	    );
	  }
	});

var ColspanRow = React.createClass({
	  render: function() {
		var colCount = this.props.colCount;
		var message = this.props.message;
		
	    return (
	    	<tr><td colSpan={colCount}>{message}</td></tr>
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