var Configuration = React.createClass({
  loadConfigurationObjectFromServer: function() {
    $.ajax({
      url: apiBaseUrl + "/api/configuration/server-config",
      success: function(jsonData) {
//  		console.log('config: ' + jsonData);
    	var data = JSON.parse(jsonData);
        this.setState({data: data});
      }.bind(this),
      error: function(xhr, status, err) {
        console.error(apiBaseUrl + "/api/configuration/server-config-base64", status, err.toString());
      }.bind(this)
    });
  },
  getInitialState: function() {
    return {data: {}};
  },
  componentDidMount: function() {
    this.loadConfigurationObjectFromServer();
  },
  render: function() {
    return (
      <div>
        <GeneralConfigurationHeader configuration={this.state.data} />
        <ClientApplications clientApplications={this.state.data.clientApplications} />
        <CorrelationSets correlationSets={this.state.data.correlationSets} />
        <DetectionPoints detectionPoints={this.state.data.detectionPoints} />
      </div>
    );
  }
});

var GeneralConfigurationHeader = React.createClass({
  render: function() {
	var config = this.props.configuration;
	
	var clientApplicationHeaderName = ('clientApplicationIdentificationHeaderName' in config && config.clientApplicationIdentificationHeaderName) ? config.clientApplicationIdentificationHeaderName : "Not Configured";
	var serverHostName = ('serverHostName' in config && config.serverHostName) ? config.serverHostName : "Not Configured";
	var serverPort = ('serverPort' in config && config.serverPort) ? config.serverPort : "Not Configured";
	var serverSocketTimeout = ('serverSocketTimeout' in config && config.serverSocketTimeout) ? config.serverSocketTimeout : "Not Configured";
	var configurationFile = ('configurationFile' in config && config.configurationFile) ? config.configurationFile : "Not Configured";
	
	//default
	var geolocationInfo = 'Disabled (Not Configured)';
	if ('geolocateIpAddresses' in config && config.geolocateIpAddresses) {
		// it is configured, need to set enabled/disabled
		if (true === config.geolocateIpAddresses) {
			if ('geolocationDatabasePath' in config && config.geolocationDatabasePath) {
				// yes geolocation and path exists
				geolocationInfo = 'Enabled (path: "' + config.geolocationDatabasePath + '")';
			} else {
				// yes geolocation, but default path
				geolocationInfo = 'Enabled (path: default)';
			}
		} else {
			geolocationInfo = 'Disabled';
		}
	} else if ('geolocateIpAddresses' in config && false === config.geolocateIpAddresses) {
		geolocationInfo = 'Disabled';
	}
	
	var geolocateIpAddresses = ('geolocateIpAddresses' in config && config.geolocateIpAddresses) ? config.geolocateIpAddresses : "Not Configured";
	
    return (
    	<div id="general_configuration">
    		<br />
    		<h2>General Configuration</h2>
    		<hr />
            <SimpleRow left="Client Application Header Name" right={clientApplicationHeaderName} />
            <SimpleRow left="Server Host Name" right={serverHostName} />
            <SimpleRow left="Server Port" right={serverPort} />
            <SimpleRow left="Server Socket Timeout (ms)" right={serverSocketTimeout} />
            <SimpleRow left="Geolocation" right={geolocationInfo} />
            <SimpleRow left="Configuration File" right={configurationFile} />
        </div>
    );
  }
});

var SimpleRow = React.createClass({
  render: function() {
    return (
      <div className="row">
    	<div className="col-md-3"><strong>{this.props.left}</strong></div>
    	<div className="col-md-9">{this.props.right}</div>
      </div>
    );
  }
});

var ClientApplications = React.createClass({
  render: function() {
	var clientApplications = this.props.clientApplications;
	var shouldRender = (!clientApplications || clientApplications.length === 0) ? "No Client Applications are currently configured" : <ClientApplicationsContent clientApplications={clientApplications}/>;
	
    return (
    	<div id="client_applications">
	    	<br />
	    	<h2>Client Applications</h2>
    		<hr />
            {shouldRender}
        </div>
    );
  }
});

//happens when there's data
var ClientApplicationsContent = React.createClass({
  render: function() {
	var clientApplications = this.props.clientApplications;

	var clientApplicationRender = clientApplications.map(function (clientApp) {
	      return (
	    	<tr>
	    	  <td>{clientApp.name}</td>
	    	  <td>{clientApp.roles.join(", ")}</td>
	    	</tr>
	      );
	    });
	
    return (
		<div className="table-responsive">
		  <table className="table table-condensed table-hover table-bordered table-striped">
		  	<tr>
	    	  <th>Application Name</th>
	    	  <th>Assigned Roles</th>
	    	</tr>
		    {clientApplicationRender}
    	  </table>
		</div>
    );
  }
});

var CorrelationSets = React.createClass({
  render: function() {
	var correlationSets = this.props.correlationSets;
	
	var shouldRender = (!correlationSets || correlationSets.length === 0) ? "No Correlation Sets are currently configured" : <CorrelationSetsContent correlationSets={correlationSets}/>;
	
    return (
    	<div id="correlation_sets">
    		<br />
    		<h2>Correlation Sets</h2>
    		<hr />
    		{shouldRender}
        </div>
    );
  }
});

//happens when there's data
var CorrelationSetsContent = React.createClass({
  render: function() {
	var correlationSets = this.props.correlationSets;

	var correlationSetRender = correlationSets.map(function (correlationSet) {
	      return (
	    	<tr>
	    	  <td>{correlationSet.clientApplications.join(", ")}</td>
	    	</tr>
	      );
	    });
	
    return (
		<div className="table-responsive">
		  <table className="table table-condensed table-hover table-bordered table-striped">
		  	<tr>
	    	  <th>Correlated Applications</th>
	    	</tr>
		    {correlationSetRender}
    	  </table>
		</div>
    );
  }
});

var DetectionPoints = React.createClass({
  render: function() {
	var detectionPoints = this.props.detectionPoints;
	
	var shouldRender = (!detectionPoints || detectionPoints.length === 0) ? "No Detection Points are currently configured" : <DetectionPointsContent detectionPoints={detectionPoints}/>;
	
    return (
    	<div id="detection_points">
    		<br />
    		<h2>Detection Points</h2>
    		<hr />
            {shouldRender}
        </div>
    );
  }
});

//happens when there's data
var DetectionPointsContent = React.createClass({
  render: function() {
	var detectionPoints = this.props.detectionPoints;
	
	var detectionPointRender = detectionPoints.map(function (detectionPoint) {
		  var threshold = detectionPoint.threshold;
		  var interval = threshold.interval;
		  var thresholdRender = threshold.count + 'x in ' + interval.duration + ' ' + interval.unit;

		  var responsesRender = <Responses responses={detectionPoint.responses} />;
		  
	      return (
	    	<tr>
	    	  <td>{detectionPoint.category}</td>
	    	  <td>{detectionPoint.label}</td>
	    	  <td>{thresholdRender}</td>
	    	  <td>{responsesRender}</td>
	    	</tr>
	      );
	    });
	
    return (
		<div className="table-responsive">
		  <table className="table table-condensed table-hover table-bordered table-striped">
		  	<tr>
	    	  <th>Category</th>
	    	  <th>ID / Label</th>
	    	  <th>Threshold</th>
	    	  <th>Responses</th>
	    	</tr>
		    {detectionPointRender}
    	  </table>
		</div>
    );
  }
});


var Responses = React.createClass({
  render: function() {
	var responses = this.props.responses;
	
	var shouldRender = (!responses || responses.length === 0) ? "No Responses are currently configured" : <ResponsesContent responses={responses}/>;
	
    return (
    	<div>
            {shouldRender}
        </div>
    );
  }
});

//happens when there's data
var ResponsesContent = React.createClass({
  render: function() {
	var responses = this.props.responses;
	
	var responseRender = responses.map(function (response) {
		  var responseStr = response.action;
		  
		  if (response.interval) {
			  responseStr += ' (maintains effect for ' + response.interval.duration + ' ' + response.interval.unit + ')';
		  }
		  
	      return (
	    	<li>
	    	  {responseStr}
	    	</li>
	      );
	    });
	
    return (
		<ol>
		    {responseRender}
		</ol>
    );
  }
});


React.render(<Configuration />, document.getElementById('react_configuration_container'));

// ace editor for xml
var AceEditor = React.createClass({
  loadXmlFromServer: function() {
	  $.ajax({
		    url: apiBaseUrl + "/api/configuration/server-config-base64",
		    success:function(result){
		    	var editor = ace.edit("editor");
		    	editor.setTheme("ace/theme/monokai");
		    	editor.getSession().setMode("ace/mode/xml");
		    	var base64value = result.value;
		    	var decoded = atob(base64value);
		    	editor.setValue(decoded);
		    	// editor.setReadOnly(true);
		    },
		    error:function(result){
		    	console.log('had an ajax error: ' + JSON.stringify(result));
		    }
		}); 
  },
  getInitialState: function() {
    return {data: []};
  },
  componentDidMount: function() {
    this.loadXmlFromServer();
  },
  render: function() {
    return (
      <div></div>
    );
  }
});

React.render(<AceEditor />, document.getElementById('react_xml_container'));
