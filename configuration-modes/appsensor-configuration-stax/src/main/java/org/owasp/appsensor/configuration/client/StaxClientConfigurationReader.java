package org.owasp.appsensor.configuration.client;


import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLResolver;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

import org.owasp.appsensor.exceptions.ConfigurationException;
import org.owasp.appsensor.util.XmlUtils;
import org.xml.sax.SAXException;

/**
 * This implementation parses the {@link ClientConfiguration} objects from the specified XML file via the StAX API.
 * 
 * @author johnmelton
 */
public class StaxClientConfigurationReader implements ClientConfigurationReader {
	
	private static final String XSD_NAMESPACE = "https://www.owasp.org/index.php/OWASP_AppSensor_Project/xsd/appsensor_client_config_2.0.xsd";
	
	private Map<String, String> namespaces = new HashMap<String, String>();
	
	public StaxClientConfigurationReader() {
		/** initialize namespaces **/
		namespaces.put(XSD_NAMESPACE, "config");
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public ClientConfiguration read() throws ConfigurationException {
		String defaultXmlLocation = "/appsensor-client-config.xml";
		String defaultXsdLocation = "/appsensor_client_config_2.0.xsd";
		
		return read(defaultXmlLocation, defaultXsdLocation);
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public ClientConfiguration read(String xml, String xsd) throws ConfigurationException {
		ClientConfiguration configuration = null;
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
			
			xmlReader = xmlFactory.createXMLStreamReader(xmlInputStream);
			
			configuration = readClientConfiguration(xmlReader);
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
	
	private ClientConfiguration readClientConfiguration(XMLStreamReader xmlReader) throws XMLStreamException {
		ClientConfiguration configuration = new ClientConfiguration();
		boolean finished = false;

		while(!finished && xmlReader.hasNext()) {
			int event = xmlReader.next();
			String name = XmlUtils.getElementQualifiedName(xmlReader, namespaces);
			
			switch(event) {			
				case XMLStreamConstants.START_ELEMENT:
					if("config:appsensor-client-config".equals(name)) {
						//
//					} else if("config:event-manager".equals(name)) {
//						readEventManager(configuration, xmlReader);
//					} else if("config:response-handler".equals(name)) {
//						readResponseHandler(configuration, xmlReader);
//					} else if("config:user-manager".equals(name)) {
//						readUserManager(configuration, xmlReader);
					} else if("config:server-connection".equals(name)) {
						configuration.setServerConnection(readServerConnection(xmlReader));
					} else {
						/** unexpected start element **/
					}
					break;
				case XMLStreamConstants.END_ELEMENT:
					if("config:appsensor-client-config".equals(name)) {
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
	
	private ServerConnection readServerConnection(XMLStreamReader xmlReader) throws XMLStreamException {
		ServerConnection serverConnection = new ServerConnection();
		boolean finished = false;
		
		serverConnection.setType(xmlReader.getAttributeValue(null, "type"));
		
		while(!finished && xmlReader.hasNext()) {
			int event = xmlReader.next();
			String name = XmlUtils.getElementQualifiedName(xmlReader, namespaces);
			
			switch(event) {
				case XMLStreamConstants.START_ELEMENT:
					if("config:protocol".equals(name)) {
						serverConnection.setProtocol(xmlReader.getElementText().trim());
					} else if("config:host".equals(name)) {
						serverConnection.setHost(xmlReader.getElementText().trim());
					} else if("config:port".equals(name)) {
						serverConnection.setPort(Integer.parseInt(xmlReader.getElementText().trim()));
					} else if("config:path".equals(name)) {
						serverConnection.setPath(xmlReader.getElementText().trim());
					} else if("config:client-application-identification-header-value".equals(name)) {
						serverConnection.setClientApplicationIdentificationHeaderValue(xmlReader.getElementText().trim());
					} else {
						/** unexpected start element **/
					}
					break;
				case XMLStreamConstants.END_ELEMENT:
					if("config:server-connection".equals(name)) {
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
		
		return serverConnection;
	}
	
//	private void readEventManager(ClientConfiguration configuration, XMLStreamReader xmlReader) throws XMLStreamException {
//		boolean finished = false;
//		
//		configuration.setEventManagerImplementation(xmlReader.getAttributeValue(null, "class"));
//		
//		while(!finished && xmlReader.hasNext()) {
//			int event = xmlReader.next();
//			String name = XmlUtils.getElementQualifiedName(xmlReader, namespaces);
//			
//			switch(event) {			
//				case XMLStreamConstants.START_ELEMENT:
//					break;
//				case XMLStreamConstants.END_ELEMENT:
//					if("config:event-manager".equals(name)) {
//						finished = true;
//					} else {
//						/** unexpected end element **/
//					}
//					break;
//				default:
//					/** unused xml element - nothing to do **/
//					break;
//			}
//		}
//	}
//	
//	private void readResponseHandler(ClientConfiguration configuration, XMLStreamReader xmlReader) throws XMLStreamException {
//		boolean finished = false;
//		
//		configuration.setResponseHandlerImplementation(xmlReader.getAttributeValue(null, "class"));
//		
//		while(!finished && xmlReader.hasNext()) {
//			int event = xmlReader.next();
//			String name = XmlUtils.getElementQualifiedName(xmlReader, namespaces);
//			
//			switch(event) {			
//				case XMLStreamConstants.START_ELEMENT:
//					break;
//				case XMLStreamConstants.END_ELEMENT:
//					if("config:response-handler".equals(name)) {
//						finished = true;
//					} else {
//						/** unexpected end element **/
//					}
//					break;
//				default:
//					/** unused xml element - nothing to do **/
//					break;
//			}
//		}
//	}
//	
//	private void readUserManager(ClientConfiguration configuration, XMLStreamReader xmlReader) throws XMLStreamException {
//		boolean finished = false;
//		
//		configuration.setUserManagerImplementation(xmlReader.getAttributeValue(null, "class"));
//		
//		while(!finished && xmlReader.hasNext()) {
//			int event = xmlReader.next();
//			String name = XmlUtils.getElementQualifiedName(xmlReader, namespaces);
//			
//			switch(event) {			
//				case XMLStreamConstants.START_ELEMENT:
//					break;
//				case XMLStreamConstants.END_ELEMENT:
//					if("config:user-manager".equals(name)) {
//						finished = true;
//					} else {
//						/** unexpected end element **/
//					}
//					break;
//				default:
//					/** unused xml element - nothing to do **/
//					break;
//			}
//		}
//	}
	
}


