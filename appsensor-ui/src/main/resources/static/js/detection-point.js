
function activateSlider(selectedTimeSpan) {
	var items =[ 'Month','Week','Day','Shift', 'Hour'];
	var s = $("#timeline-slider");

	s.slider({
	  min:1,
	  max:items.length,
	  slide: function( event, ui ) {
		  var selectedTimeSpan = items[ui.value - 1].toUpperCase();
		  
		  var detectionPointLabel = $("#detection-point-label").text();
		  
		  initReact(selectedTimeSpan, detectionPointLabel);
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
  	var monthAttacks = findCount('MONTH', 'ATTACK', data);
  	var weekEvents = findCount('WEEK', 'EVENT', data);
  	var weekAttacks = findCount('WEEK', 'ATTACK', data);
  	var dayEvents = findCount('DAY', 'EVENT', data);
  	var dayAttacks = findCount('DAY', 'ATTACK', data);
  	var shiftEvents = findCount('SHIFT', 'EVENT', data);
  	var shiftAttacks = findCount('SHIFT', 'ATTACK', data);
  	var hourEvents = findCount('HOUR', 'EVENT', data);
  	var hourAttacks = findCount('HOUR', 'ATTACK', data);
  	
	$("#Month-slider-label").html('Month <span class="badge" title="' 
			+ monthEvents + ' events / ' + monthAttacks + ' attacks">' + monthEvents + ' / ' + monthAttacks + '</span>');
	$("#Week-slider-label").html('Week <span class="badge" title="' 
			+ weekEvents + ' events / ' + weekAttacks + ' attacks">' + weekEvents + ' / ' + weekAttacks + '</span>');
	$("#Day-slider-label").html('Day <span class="badge" title="' 
			+ dayEvents + ' events / ' + dayAttacks + ' attacks">' + dayEvents + ' / ' + dayAttacks + '</span>');
	$("#Shift-slider-label").html('Shift <span class="badge" title="' 
			+ shiftEvents + ' events / ' + shiftAttacks + ' attacks">' + shiftEvents + ' / ' + shiftAttacks + '</span>');
	$("#Hour-slider-label").html('Hour <span class="badge" title="' 
			+ hourEvents + ' events / ' + hourAttacks + ' attacks">' + hourEvents + ' / ' + hourAttacks + '</span>');
}

function displayMorris(viewObject) {
	  //clean up contents and start over
  	  $("#label-count-graph").empty();
	  
      var viewData = JSON.parse(viewObject.data);
      var viewXKey = viewObject.xkey;
      var viewYKeys = viewObject.ykeys;
      var viewLabels = viewObject.labels;

      Morris.Area({
    	  element: 'label-count-graph',
    	  data: JSON.parse(viewObject.data),
    	  xkey: viewObject.xkey,
    	  ykeys: viewObject.ykeys,
    	  labels: viewObject.labels,
    	  behaveLikeLine: true
    	});
}

var DetectionPointDetail = React.createClass({
	  loadDetectionPointObjectFromServer: function() {
		  
		  	var selectedTimeSpan = this.props.selectedTimeSpan;
		  	
		  	var timestamp = getTimestamp(selectedTimeSpan);
		  	var detectionPointLabel = this.props.detectionPointLabel;
		  
		    $.ajax({
		      url: apiBaseUrl + '/api/detection-points/' + detectionPointLabel + '/all?earliest=' + encodeURIComponent(timestamp) + '&limit=10&slices=10',
		      success: function(data) {
		    	this.setState({data: data});
		        
		    	console.log('pulled data back and refreshed ui at ' + timestamp);

		    	displayMorris(data.groupedDetectionPoints);
		        updateSlider(data.byTimeFrame);
		        
		      }.bind(this),
		      error: function(xhr, status, err) {
		        console.error(apiBaseUrl + '/api/detection-points/{detectionPointLabel}/all?earliest=' + timestamp + '&limit=10&slices=10', status, err.toString());
		      }.bind(this)
		    });
	  },
	  
	  getInitialState: function() {
	    return {data: {}};
	  },
	  componentDidMount: function() {

		  var selectedTimeSpan = this.props.selectedTimeSpan;
		
		  activateSlider(selectedTimeSpan);
	    
		  this.loadDetectionPointObjectFromServer();
		  
		  var intervalVar = setInterval(this.loadDetectionPointObjectFromServer, 60 * 1000);	// refresh once per minute
		  setIntervals.push(intervalVar);
	  },
	  
	  render: function() {
		var timestamp = getTimestamp(this.props.selectedTimeSpan);
		
	    return (
			<div class="row">
			
			  <Slider data={this.state.data.byTimeFrame} />
			  
			  <br /><br />
			  
			  <div className="col-md-8">
			  	  <h2>Information For Detection Point {this.props.detectionPointLabel}</h2>
			  	  <hr />
				  <DetectionPointLabelCount detectionPointLabel={this.props.detectionPointLabel} />
				  <LatestEvents latestEvents={this.state.data.recentEvents} />
				  <LatestAttacks latestAttacks={this.state.data.recentAttacks} />
			  </div>
			  
			  <div className="col-md-4">
			  	  	<LastUpdated timestamp={timestamp} />
			  	  	<br />
			  	  	<ByClientApplication byClientApplication={this.state.data.byClientApplication} />
			  	  	<TopUsers topUsers={this.state.data.topUsers} />
			  	  	<DetectionPointConfiguration configuration={this.state.data.configuration} />
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

var DetectionPointLabelCount = React.createClass({
	  render: function() {
		return (
    		<div>
    		<h4 className="dashboard-section-header"><strong>Events By Count</strong></h4>
    		<div id='label-count-graph'>
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
			  
			  var attackCount = '';
			  if (byApp.count.ATTACK) {
				  if(eventCount) {
					  attackCount += ', ';
				  }
				  
				  attackCount += byApp.count.ATTACK + ' attacks';
			  }
			  
			  var countString = eventCount + attackCount;
			
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

var DetectionPointConfiguration = React.createClass({
	  render: function() {
		  var configuration = this.props.configuration;
		  
		  var shouldRender = ( $.isEmptyObject(configuration) ) ? 
					<EmptyTable header="Associated Configuration" message="There is no associated configuration for this detection point label." />: 
						<DetectionPointConfigurationContent configuration={configuration} />;
			
		    return (
		    		<div>
		    			{shouldRender}
		    		</div>
		    );
	  }
	});

var DetectionPointConfigurationContent = React.createClass({
	  render: function() {
		var configuration = JSON.parse(this.props.configuration);
		
		var configRender = configuration.map(function (item) {
			  var thresholdContent = item.threshold.count + ' in ' + item.threshold.interval.duration + ' ' + item.threshold.interval.unit;
			  
			  var responsesRender = item.responses.map(function (response) {
				  
				  var responseContent = response.action; 
				  
				  if(response.interval) {
					  responseContent += ' ( for ' + response.interval.duration + ' ' + response.interval.unit + ')';
				  }

			      return (
			    	<li>{responseContent}</li>
			      );
			    });
			  
		      return (
		    	<tr>
		    	  <td>
		    	  	<strong>Category:</strong> {item.category}	<br />
		    	  	<strong>Threshold:</strong> {thresholdContent}	<br />
		    	  	<strong>Responses:</strong><ul> {responsesRender}</ul>
		    	  </td>
		    	</tr>
		      );
		    });
		
	    return (
	    	<div className="table-responsive">
		    	<table className="table table-hover table-bordered">
				    <tr>
				    	<th className="dashboard-section-header">Associated Configuration</th>
				    </tr>
				    {configRender}
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

function initReact(selectedTimeSpan, detectionPointLabel) {
	
	// remove any previous reset intervals
	$.each( setIntervals, function( i, val ) {
		  clearInterval(val);
		  var index = setIntervals.indexOf(val);
		  if (index > -1) {
			  setIntervals.splice(index, 1);
		  }
		});
	
	React.unmountComponentAtNode(document.getElementById('react_container'));
	React.render(<DetectionPointDetail selectedTimeSpan={selectedTimeSpan} detectionPointLabel={detectionPointLabel} />, document.getElementById('react_container'));
}

$(function() {
	keepalive();

	var detectionPointLabel = $("#detection-point-label").text();

	// on first load of the page, find the shortest time frame that has events and load it, defaulting to month if none are found
	$.ajax({
	      url: apiBaseUrl + '/api/detection-points/' + detectionPointLabel + '/by-time-frame',
	      
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
	    	  	
		  		initReact(span, detectionPointLabel);
	      },
	      error: function(data) {
	    	  console.log('Failure contacting appsensor service for loading updateSlider.');
	      }
	  });
});