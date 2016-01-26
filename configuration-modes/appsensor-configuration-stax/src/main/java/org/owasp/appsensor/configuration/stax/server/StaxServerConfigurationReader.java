package org.owasp.appsensor.configuration.stax.server;


import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.List;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLResolver;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

import org.owasp.appsensor.core.ClientApplication;
import org.owasp.appsensor.core.DetectionPoint;
import org.owasp.appsensor.core.IPAddress;
import org.owasp.appsensor.core.Interval;
import org.owasp.appsensor.core.Response;
import org.owasp.appsensor.core.Threshold;
import org.owasp.appsensor.core.accesscontrol.Role;
import org.owasp.appsensor.core.configuration.server.ServerConfiguration;
import org.owasp.appsensor.core.configuration.server.ServerConfigurationReader;
import org.owasp.appsensor.core.correlation.CorrelationSet;
import org.owasp.appsensor.core.exceptions.ConfigurationException;
import org.owasp.appsensor.core.geolocation.GeoLocation;
import org.owasp.appsensor.core.util.XmlUtils;
import org.xml.sax.SAXException;

/**
 * This implementation parses the {@link ServerConfiguration} objects 
 * from the specified XML file via the StAX API.
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public class StaxServerConfigurationReader implements ServerConfigurationReader {
	
	private static final String XSD_NAMESPACE = "https://www.owasp.org/index.php/OWASP_AppSensor_Project/xsd/appsensor_server_config_2.0.xsd";
	
	private Map<String, String> namespaces = new HashMap<String, String>();
	
	public StaxServerConfigurationReader() {
		/** initialize namespaces **/
		namespaces.put(XSD_NAMESPACE, "config");
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public ServerConfiguration read() throws ConfigurationException {
		String defaultXmlLocation = "/appsensor-server-config.xml";
		String defaultXsdLocation = "/appsensor_server_config_2.0.xsd";
		
		return read(defaultXmlLocation, defaultXsdLocation);
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public ServerConfiguration read(String xml, String xsd) throws ConfigurationException {
		ServerConfiguration configuration = null;
		InputStream xmlInputStream = null;
		XMLStreamReader xmlReader = null;
		
		try {
			XMLInputFactory xmlFactory = XMLInputFactory.newInstance();
			
			xmlFactory.setProperty(XMLInputFactory.IS_REPLACING_ENTITY_REFERENCES, Boolean.FALSE);
			xmlFactory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, Boolean.FALSE);
			xmlFactory.setProperty(XMLInputFactory.IS_NAMESPACE_AWARE, Boolean.TRUE);
			xmlFactory.setProperty(XMLInputFactory.IS_VALIDATING, Boolean.FALSE);
			xmlFactory.setXMLResolver(new XMLResolver() {
				@Override
				public Object resolveEntity(String arg0, String arg1, String arg2, String arg3) throws XMLStreamException {
					return new ByteArrayInputStream(new byte[0]);
				}
			});
			
			XmlUtils.validateXMLSchema(xsd, xml);
			
			xmlInputStream = getClass().getResourceAsStream(xml);
			
			//try loading from classpath first - fallback to disk
			if (xmlInputStream == null) {
				File xmlFile = new File(xml);
				xmlInputStream = new FileInputStream(xmlFile);
			}
			
			xmlReader = xmlFactory.createXMLStreamReader(xmlInputStream);
			
			configuration = readServerConfiguration(xmlReader);
			
			if (configuration != null) {
				URL xmlUrl = getClass().getResource(xml);
				if (xmlUrl != null) {
					File configurationFile = new File(xmlUrl.getFile());
					
					if (configurationFile != null && configurationFile.exists()) {
						configuration.setConfigurationFile(configurationFile);
					}
				} else {
					//try a disk-based backup
					File configurationFile = new File(xml);
					
					if (configurationFile != null && configurationFile.exists()) {
						configuration.setConfigurationFile(configurationFile);
					}
				}
			}
			
		} catch(XMLStreamException | IOException | SAXException e) {
			throw new ConfigurationException(e.getMessage(), e);
		} finally {
			if(xmlReader != null) {
				try {
					xmlReader.close();
				} catch (XMLStreamException xse) {
					/** give up **/
				}
			}
			
			if(xmlInputStream != null) {
				try {
					xmlInputStream.close();
				} catch (IOException ioe) {
					/** give up **/
				}
			}
		}
		
		return configuration;
	}
	
	private ServerConfiguration readServerConfiguration(XMLStreamReader xmlReader) throws XMLStreamException {
		ServerConfiguration configuration = new StaxServerConfiguration(false);
		boolean finished = false;
		
		while(!finished && xmlReader.hasNext()) {
			int event = xmlReader.next();
			String name = XmlUtils.getElementQualifiedName(xmlReader, namespaces);

			switch(event) {		
				case XMLStreamConstants.START_ELEMENT:
					if("config:appsensor-server-config".equals(name)) {
						//
					} else if("config:client-application-identification-header-name".equals(name)) {
						configuration.setClientApplicationIdentificationHeaderName(xmlReader.getElementText().trim());
					} else if("config:server-host-name".equals(name)) {
						configuration.setServerHostName(xmlReader.getElementText().trim());
					} else if("config:server-port".equals(name)) {
						configuration.setServerPort(Integer.parseInt(xmlReader.getElementText().trim()));
					} else if("config:server-socket-timeout-ms".equals(name)) {
						configuration.setServerSocketTimeout(Integer.parseInt(xmlReader.getElementText().trim()));
					} else if("config:geolocation".equals(name)) {
						boolean useGeolocation = "true".equalsIgnoreCase(xmlReader.getAttributeValue(null, "enabled").trim()) ? true : false;
						
						String databasePath = xmlReader.getAttributeValue(null, "databasePath");
						databasePath = databasePath != null ? databasePath.trim() : databasePath;
						
						configuration.setGeolocateIpAddresses(useGeolocation);
						configuration.setGeolocationDatabasePath(databasePath);
					} else if("config:client-applications".equals(name)) {
						configuration.getClientApplications().addAll(readClientApplications(xmlReader));
					} else if("config:correlation-config".equals(name)) {
						configuration.getCorrelationSets().addAll(readCorrelationSets(xmlReader));
					} else if("config:detection-point".equals(name)) {
						configuration.getDetectionPoints().add(readDetectionPoint(xmlReader));
					} else if("config:clients".equals(name)) {
						configuration.getCustomDetectionPoints().putAll(readCustomDetectionPoints(xmlReader));
					} else {
						/** unexpected start element **/
					}
					break;
				case XMLStreamConstants.END_ELEMENT:
					if("config:appsensor-server-config".equals(name)) {
						finished = true;
					} else {
						/** unexpected end element **/
					}
					break;
				default:
					/** unused xml element - nothing to do **/
					break;
			}
		}
		
		return configuration;
	}
	
	private Collection<ClientApplication> readClientApplications(XMLStreamReader xmlReader) throws XMLStreamException {
		Collection<ClientApplication> clientApplications = new ArrayList<>();
		boolean finished = false;
		
		ClientApplication clientApplication = null;
		
		while(!finished && xmlReader.hasNext()) {
			int event = xmlReader.next();
			String name = XmlUtils.getElementQualifiedName(xmlReader, namespaces);
			
			switch(event) {
				case XMLStreamConstants.START_ELEMENT:
					if("config:client-application".equals(name)) {
						clientApplication = new ClientApplication();
					} else if("config:name".equals(name)) {
						clientApplication.setName(xmlReader.getElementText().trim());
					} else if("config:role".equals(name)) {
						clientApplication.getRoles().add(Role.valueOf(xmlReader.getElementText().trim()));
					} else if("config:ip-address".equals(name)) {
						double latitude = Double.parseDouble(xmlReader.getAttributeValue(null, "latitude").trim());
						double longitude = Double.parseDouble(xmlReader.getAttributeValue(null, "longitude").trim());
						GeoLocation geoLocation = new GeoLocation(latitude, longitude);
						String ipAddressStr = xmlReader.getElementText().trim();
						IPAddress ipAddress = new IPAddress(ipAddressStr, geoLocation);
						clientApplication.setIpAddress(ipAddress);
					} else {
						/** unexpected start element **/
					}
					break;
				case XMLStreamConstants.END_ELEMENT:
					if("config:client-application".equals(name)) {
						clientApplications.add(clientApplication);
					} else if("config:client-applications".equals(name)) {
						finished = true;
					} else {
						/** unexpected end element **/
					}
					break;
				default:
					/** unused xml element - nothing to do **/
					break;
			}
		}
		
		return clientApplications;
	}
	
	private Collection<CorrelationSet> readCorrelationSets(XMLStreamReader xmlReader) throws XMLStreamException {
		Collection<CorrelationSet> correlationSets = new ArrayList<>();
		boolean finished = false;
		
		CorrelationSet correlationSet = null;
		
		while(!finished && xmlReader.hasNext()) {
			int event = xmlReader.next();
			String name = XmlUtils.getElementQualifiedName(xmlReader, namespaces);
			
			switch(event) {
				case XMLStreamConstants.START_ELEMENT:
					if("config:correlated-client-set".equals(name)) {
						correlationSet = new CorrelationSet();
					} else if("config:client-application-name".equals(name)) {
						correlationSet.getClientApplications().add(xmlReader.getElementText().trim());
					} else {
						/** unexpected start element **/
					}
					break;
				case XMLStreamConstants.END_ELEMENT:
					if("config:correlated-client-set".equals(name)) {
						correlationSets.add(correlationSet);
					} else if("config:correlation-config".equals(name)) {
						finished = true;
					} else {
						/** unexpected end element **/
					}
					break;
				default:
					/** unused xml element - nothing to do **/
					break;
			}
		}
		
		return correlationSets;
	}
	
	private DetectionPoint readDetectionPoint(XMLStreamReader xmlReader) throws XMLStreamException {
		DetectionPoint detectionPoint = new DetectionPoint();
		boolean finished = false;
		
		while(!finished && xmlReader.hasNext()) {
			int event = xmlReader.next();
			String name = XmlUtils.getElementQualifiedName(xmlReader, namespaces);
			
			switch(event) {
				case XMLStreamConstants.START_ELEMENT:
					if("config:category".equals(name)) {
						detectionPoint.setCategory(xmlReader.getElementText().trim());
					} else if("config:id".equals(name)) {
						detectionPoint.setLabel(xmlReader.getElementText().trim());
					} else if("config:threshold".equals(name)) {
						detectionPoint.setThreshold(readThreshold(xmlReader));
					} else if("config:response".equals(name)) {
						detectionPoint.getResponses().add(readResponse(xmlReader));
					} else {
						/** unexpected start element **/
					}
					break;
				case XMLStreamConstants.END_ELEMENT:
					if("config:detection-point".equals(name)) {
						finished = true;
					} else {
						/** unexpected end element **/
					}
					break;
				default:
					/** unused xml element - nothing to do **/
					break;
			}
		}
		
		return detectionPoint;
	}
	
	private HashMap<String,List<DetectionPoint>> readCustomDetectionPoints(XMLStreamReader xmlReader) throws XMLStreamException {
		DetectionPoint detectionPoint = new DetectionPoint();
		HashMap<String,List<DetectionPoint>> customPoints = new HashMap<String,List<DetectionPoint>>();
		String clientName = "";
		boolean finished = false;
		
		while(!finished && xmlReader.hasNext()) {
			int event = xmlReader.next();
			String name = XmlUtils.getElementQualifiedName(xmlReader, namespaces);
			List<DetectionPoint> customList = new ArrayList<DetectionPoint>();
			
			
			switch(event) {
				case XMLStreamConstants.START_ELEMENT:
				if("config:client-name".equals(name)) {
						clientName = xmlReader.getElementText().trim();
					}else if("config:detection-point".equals(name)) {
						customList.add(readDetectionPoint(xmlReader));
						
					}else {
						/** unexpected start element **/
					}
					break;
				case XMLStreamConstants.END_ELEMENT:
					if("config:clients".equals(name)) {
						finished = true;
					}else if("config:client".equals(name)) {	
						customPoints.put(clientName,customList);
						customList = new ArrayList<DetectionPoint>();
					}else {
					
						/** unexpected end element **/
					}
					break;
				default:
					/** unused xml element - nothing to do **/
					break;
			}
			
			//clientName = "";
		}
		
		return customPoints;
	}
	
	private Threshold readThreshold(XMLStreamReader xmlReader) throws XMLStreamException {
		Threshold threshold = new Threshold();
		boolean finished = false;
		
		while(!finished && xmlReader.hasNext()) {
			int event = xmlReader.next();
			String name = XmlUtils.getElementQualifiedName(xmlReader, namespaces);
			
			switch(event) {
				case XMLStreamConstants.START_ELEMENT:
					if("config:count".equals(name)) {
						threshold.setCount(Integer.parseInt(xmlReader.getElementText().trim()));
					} else if("config:interval".equals(name)) {
						Interval interval = new Interval();
						interval.setUnit(xmlReader.getAttributeValue(null, "unit").trim());
						interval.setDuration(Integer.parseInt(xmlReader.getElementText().trim()));
						threshold.setInterval(interval);
					} else {
						/** unexpected start element **/
					}
					break;
				case XMLStreamConstants.END_ELEMENT:
					if("config:threshold".equals(name)) {
						finished = true;
					} else {
						/** unexpected end element **/
					}
					break;
				default:
					/** unused xml element - nothing to do **/
					break;
			}
		}
		
		return threshold;
	}
	
	private Response readResponse(XMLStreamReader xmlReader) throws XMLStreamException {
		Response response = new Response();
		boolean finished = false;
		
		while(!finished && xmlReader.hasNext()) {
			int event = xmlReader.next();
			String name = XmlUtils.getElementQualifiedName(xmlReader, namespaces);
			
			switch(event) {
				case XMLStreamConstants.START_ELEMENT:
					if("config:action".equals(name)) {
						response.setAction(xmlReader.getElementText().trim());
					} else if("config:interval".equals(name)) {
						Interval interval = new Interval();
						interval.setUnit(xmlReader.getAttributeValue(null, "unit").trim());
						interval.setDuration(Integer.parseInt(xmlReader.getElementText().trim()));
						response.setInterval(interval);
					} else {
						/** unexpected start element **/
					}
					break;
				case XMLStreamConstants.END_ELEMENT:
					if("config:response".equals(name)) {
						finished = true;
					} else {
						/** unexpected end element **/
					}
					break;
				default:
					/** unused xml element - nothing to do **/
					break;
			}
		}
		
		return response;
	}
	
}


