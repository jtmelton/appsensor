package org.owasp.appsensor.configuration.client;

public interface ServerConnection {
	
	public String getType();
	
	public ServerConnection setType(String type);
	
	public String getProtocol();
	
	public ServerConnection setProtocol(String protocol);
	
	public String getHost();
	
	public ServerConnection setHost(String host);
	
	public int getPort();
	
	public ServerConnection setPort(int port);
	
	public String getPath();
	
	public ServerConnection setPath(String path);
	
}
