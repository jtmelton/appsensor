package org.owasp.appsensor.reporting;

/**
 * Simple bean representing a generic key-value pair for json data.
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
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
