package org.owasp.appsensor.reporting;


public class WebSocketJsonObject {
	
	private String dataType;
	private Object dataValue;
	
	public WebSocketJsonObject() { }
	
	public WebSocketJsonObject(String dataType, Object dataValue) {
		setDataType(dataType);
		setDataValue(dataValue);
	}

	public String getDataType() {
		return dataType;
	}

	public void setDataType(String dataType) {
		this.dataType = dataType;
	}

	public Object getDataValue() {
		return dataValue;
	}

	public void setDataValue(Object dataValue) {
		this.dataValue = dataValue;
	}
	
}
