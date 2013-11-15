package org.owasp.appsensor.configuration.server;

import java.io.IOException;
import java.io.InputStream;
import java.text.ParseException;

import javax.xml.XMLConstants;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.Unmarshaller;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;



public class XmlServerConfigurationReader implements ServerConfigurationReader {
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public ServerConfiguration read() throws ParseException {
		String defaultXmlLocation = "/appsensor-server-config.xml";
		String defaultXsdLocation = "/appsensor_server_config_2.0.xsd";
		
		return read(defaultXmlLocation, defaultXsdLocation);
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public ServerConfiguration read(String configurationLocation, String validatorLocation) throws ParseException {
		ServerConfiguration configuration = readConfiguration(configurationLocation, validatorLocation);
		
		return configuration;
	}
	
	private ServerConfiguration readConfiguration(String xml, String xsd) throws ParseException {
		ServerConfiguration configuration = new ServerConfiguration();
		
		InputStream xsdStream = null;
		InputStream xmlStream = null;
		
		try {
			xsdStream = getClass().getResourceAsStream(xsd);
			xmlStream = getClass().getResourceAsStream(xml);

			JAXBContext jaxbContext = JAXBContext.newInstance(ServerConfiguration.class);
			Unmarshaller unMarshaller = jaxbContext.createUnmarshaller();

			//do validation
			Schema schema = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI).newSchema(new StreamSource(xsdStream));
			unMarshaller.setSchema(schema);
			
			// unmarshal xml -> java
			configuration = (ServerConfiguration) unMarshaller.unmarshal(xmlStream);

		} catch (Exception e) {
			// some exception occured
			e.printStackTrace();
			throw new ParseException("Could not load " + xml + " configuration file properly.", 0);
		} finally {
    		try {
    			xmlStream.close();
			} catch (IOException e) {
				//ignore
			} finally {
				xmlStream = null;
			}
        }
		
		return configuration;
	}
	
}
