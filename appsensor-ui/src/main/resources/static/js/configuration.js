var editor = ace.edit("editor");
	
function initAce() {
	editor.setTheme("ace/theme/monokai");
	editor.getSession().setMode("ace/mode/xml");
}

function loadConfigurationObject() {
	$.ajax({
	    url: apiBaseUrl + "/api/configuration/server-config",
	    success:function(result){
	    	alert('loaded config');
	    },
	    error:function(result){
	    	console.log('had an ajax error: ' + JSON.stringify(result));
	    }
	}); 
}

function loadConfigurationXml() {
	$.ajax({
	    url: apiBaseUrl + "/api/configuration/server-config-base64",
	    success:function(result){
	    	var base64value = result.value;
	    	var decoded = atob(base64value);
	    	editor.setValue(decoded);
	    	
	    	alert('set data in ace');
	    },
	    error:function(result){
	    	console.log('had an ajax error: ' + JSON.stringify(result));
	    }
	}); 
}

$(function() {
	initAce();
	loadConfigurationObject();
	loadConfigurationXml();
});
 