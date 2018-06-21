
function activateSlider(selectedTimeSpan) {
	var items =[ 'Month','Week','Day','Shift', 'Hour'];
	var s = $("#timeline-slider");

	s.slider({
	  min:1,
	  max:items.length,
	  slide: function( event, ui ) {
		  var selectedTimeSpan = items[ui.value - 1].toUpperCase();
		  
		  var username = $("#username-detail").text();
		  
		  initReact(selectedTimeSpan, username);
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
  	  $("#type-count-graph").empty();
	  
      var viewData = JSON.parse(viewObject.data);
      var viewXKey = viewObject.xkey;
      var viewYKeys = viewObject.ykeys;
      var viewLabels = viewObject.labels;

      Morris.Area({
    	  element: 'type-count-graph',
    	  data: JSON.parse(viewObject.data),
    	  xkey: viewObject.xkey,
    	  ykeys: viewObject.ykeys,
    	  labels: viewObject.labels,
    	  behaveLikeLine: true
    	});
}

var UserDetail = React.createClass({
	  loadUserObjectFromServer: function() {
		  
		  	var selectedTimeSpan = this.props.selectedTimeSpan;
		  	
		  	var timestamp = getTimestamp(selectedTimeSpan);
		  	var username = this.props.username;
		  
		    $.ajax({
		      url: apiBaseUrl + '/api/users/' + username + '/all?earliest=' + encodeURIComponent(timestamp) + '&limit=10&slices=10',
		      success: function(data) {
		    	this.setState({data: data});
		        
		    	console.log('pulled data back and refreshed ui at ' + timestamp);

		    	displayMorris(data.groupedUsers);
		        updateSlider(data.byTimeFrame);
		        
		      }.bind(this),
		      error: function(xhr, status, err) {
		        console.error(apiBaseUrl + '/api/users/{username}/all?earliest=' + timestamp + '&limit=10&slices=10', status, err.toString());
		      }.bind(this)
		    });
	  },
	  
	  getInitialState: function() {
	    return {data: {}};
	  },
	  componentDidMount: function() {

		  var selectedTimeSpan = this.props.selectedTimeSpan;
		
		  activateSlider(selectedTimeSpan);
	    
		  this.loadUserObjectFromServer();
		  
		  var intervalVar = setInterval(this.loadUserObjectFromServer, 60 * 1000);	// refresh once per minute
		  setIntervals.push(intervalVar);
	  },
	  
	  render: function() {
		var timestamp = getTimestamp(this.props.selectedTimeSpan);
		
	    return (
			<div class="row">
			
			  <Slider data={this.state.data.byTimeFrame} />
			  
			  <br /><br />
			  
			  <div className="col-md-8">
			  	  <h2>Information For User: {this.props.username}</h2>
			  	  <hr />
				  <TypeCount />
				  <LatestEvents latestEvents={this.state.data.recentEvents} />
				  <LatestAttacks latestAttacks={this.state.data.recentAttacks} />
				  <LatestResponses latestResponses={this.state.data.recentResponses} />
			  </div>
			  
			  <div className="col-md-4">
			  	  	<LastUpdated timestamp={timestamp} />
			  	  	<br />
			  	  	<ByClientApplication byClientApplication={this.state.data.byClientApplication} />
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

var TypeCount = React.createClass({
	  render: function() {
		return (
    		<div>
    		<h4 className="dashboard-section-header"><strong>By Count</strong></h4>
    		<div id='type-count-graph'>
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

var LatestEvents = React.createClass({
	  render: function() {
		  var latestEvents = this.props.latestEvents;
		  
		  var shouldRender = ( $.isEmptyObject(latestEvents) ) ? 
					<EmptyTable header="Latest Events" message="There are no events found to be active in this time period." />: 
						<LatestEventsContent latestEvents={latestEvents} />;
			
		    return (
		    		<div>
		    			{shouldRender}
		    		</div>
		    );
	  }
	});

var LatestEventsContent = React.createClass({
	  render: function() {
		var latestEvents = this.props.latestEvents;

		var latestEventRender = latestEvents.map(function (latestEvent) {
		      return (
		    	<tr>
		    	  <td>{latestEvent.detectionPoint.category}</td>
		    	  <td>{latestEvent.user.username}</td>
		    	  <td>{latestEvent.detectionSystem.detectionSystemId}</td>
		    	  <td>{latestEvent.timestamp}</td>
		    	</tr>
		      );
		    });

		return (
			<div>
				<h4 className="dashboard-section-header"><strong>Latest Events</strong></h4>
				<div className="table-responsive">
				  <table className="table table-condensed table-hover table-bordered table-striped">
				  	<tr>
			    	  <th>Category</th>
			    	  <th>User</th>
			    	  <th>Detection System</th>
			    	  <th>Timestamp</th>
			    	</tr>
				    {latestEventRender}
		    	  </table>
				</div>
			</div>
	    );
	  }
	});		

var LatestAttacks = React.createClass({
	  render: function() {
		  var latestAttacks = this.props.latestAttacks;
		  
		  var shouldRender = ( $.isEmptyObject(latestAttacks) ) ? 
					<EmptyTable header="Latest Attacks" message="There are no attacks found to be active in this time period." />: 
						<LatestAttacksContent latestAttacks={latestAttacks} />;
			
		    return (
		    		<div>
		    			{shouldRender}
		    		</div>
		    );
	  }
	});

var LatestAttacksContent = React.createClass({
	  render: function() {
		var latestAttacks = this.props.latestAttacks;

		var latestAttackRender = latestAttacks.map(function (latestAttack) {
		      return (
		    	<tr>
		    	  <td>{latestAttack.detectionPoint.category}</td>
		    	  <td>{latestAttack.user.username}</td>
		    	  <td>{latestAttack.detectionSystem.detectionSystemId}</td>
		    	  <td>{latestAttack.timestamp}</td>
		    	</tr>
		      );
		    });

		return (
			<div>
				<h4 className="dashboard-section-header"><strong>Latest Attacks</strong></h4>
				<div className="table-responsive">
				  <table className="table table-condensed table-hover table-bordered table-striped">
				  	<tr>
			    	  <th>Category</th>
			    	  <th>User</th>
			    	  <th>Detection System</th>
			    	  <th>Timestamp</th>
			    	</tr>
				    {latestAttackRender}
		    	  </table>
				</div>
			</div>
	    );
	  }
	});		

var LatestResponses = React.createClass({
	  render: function() {
		  var latestResponses = this.props.latestResponses;
		  
		  var shouldRender = ( $.isEmptyObject(latestResponses) ) ? 
					<EmptyTable header="Latest Responses" message="There are no responses found to be active in this time period." />: 
						<LatestResponsesContent latestResponses={latestResponses} />;
			
		    return (
		    		<div>
		    			{shouldRender}
		    		</div>
		    );
	  }
	});

var LatestResponsesContent = React.createClass({
	  render: function() {
		var latestResponses = this.props.latestResponses;

		var latestResponseRender = latestResponses.map(function (latestResponse) {
			  
			  var responseContent = latestResponse.action; 
			  
			  if(latestResponse.interval) {
				  responseContent += ' ( for ' + latestResponse.interval.duration + ' ' + latestResponse.interval.unit + ')';
			  }
			  
		      return (
		    	<tr>
		    	  <td>{responseContent}</td>
		    	  <td>{latestResponse.user.username}</td>
		    	  <td>{latestResponse.detectionSystem.detectionSystemId}</td>
		    	  <td>{latestResponse.timestamp}</td>
		    	</tr>
		      );
		    });

		return (
			<div>
				<h4 className="dashboard-section-header"><strong>Latest Responses</strong></h4>
				<div className="table-responsive">
				  <table className="table table-condensed table-hover table-bordered table-striped">
				  	<tr>
			    	  <th>Action</th>
			    	  <th>User</th>
			    	  <th>Detection System</th>
			    	  <th>Timestamp</th>
			    	</tr>
				    {latestResponseRender}
		    	  </table>
				</div>
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


var ByClientApplication = React.createClass({
	  render: function() {
		  var byClientApplication = this.props.byClientApplication;
		  
		  var shouldRender = ( $.isEmptyObject(byClientApplication) || $.isEmptyObject(JSON.parse(byClientApplication).backingMap) ) ? 
					<EmptyTable header="Seen By These Client Applications" message="There are no client applications found to be active in this time period." />: 
						<ByClientApplicationContent byClientApplication={byClientApplication} />;
			
		    return (
		    		<div>
		    			{shouldRender}
		    		</div>
		    );
	  }
	});

var ByClientApplicationContent = React.createClass({
	  render: function() {
		var byClientApplication = JSON.parse(this.props.byClientApplication).backingMap;
		
		var byAppArray = [], item;

		for (key in byClientApplication) {
		    item = {};
		    item.name = key;
		    item.count = byClientApplication[key];
		    byAppArray.push(item);
		}
		
		var byAppRender = byAppArray.map(function (byApp) {
			  var eventCount;
			  
			  if (byApp.count.EVENT) {
				  eventCount = byApp.count.EVENT + ' events';
			  }
			  
			  var responseCount = '';
			  if (byApp.count.RESPONSE) {
				  if(eventCount) {
					  responseCount += ', ';
				  }
				  
				  responseCount += byApp.count.RESPONSE + ' responses';
			  }
			  
			  var countString = eventCount + responseCount;
			
		      return (
		    	<tr>
		    	  <td>{byApp.name} ({countString})</td>
		    	</tr>
		      );
		    });
		
	    return (
	    	<div className="table-responsive">
		    	<table className="table table-hover table-bordered">
				    <tr>
				    	<th className="dashboard-section-header">Seen By These Client Applications</th>
				    </tr>
				    {byAppRender}
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
		
		var activeResponseRender = activeResponses.map(function (activeResponse) {
			 var actionContent = activeResponse.action; 
			  
			  if(activeResponse.interval) {
				  actionContent += ' ( for ' + activeResponse.interval.duration + ' ' + activeResponse.interval.unit + ')';
			  }
			  
		      return (
		    	<tr>
		    	  <td>{actionContent} sent to {activeResponse.detectionSystem.detectionSystemId} at {activeResponse.timestamp}</td>
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

function initReact(selectedTimeSpan, username) {
	
	// remove any previous reset intervals
	$.each( setIntervals, function( i, val ) {
		  clearInterval(val);
		  var index = setIntervals.indexOf(val);
		  if (index > -1) {
			  setIntervals.splice(index, 1);
		  }
		});
	
	React.unmountComponentAtNode(document.getElementById('react_container'));
	React.render(<UserDetail selectedTimeSpan={selectedTimeSpan} username={username} />, document.getElementById('react_container'));
}

$(function() {
	keepalive();

	var username = $("#username-detail").text();
	
	// on first load of the page, find the shortest time frame that has events and load it, defaulting to month if none are found
	$.ajax({
		  url: apiBaseUrl + '/api/users/' + username + '/by-time-frame',
	      
	      success: function(data) {

//	    	  	console.log('grabbed dashboard data: ' + prettyPrint(data));
	    	  
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
	    	  	
		  		initReact(span, username);
	      },
	      error: function(data) {
	    	  console.log('Failure contacting appsensor service for loading updateSlider.');
	      }
	  });
});