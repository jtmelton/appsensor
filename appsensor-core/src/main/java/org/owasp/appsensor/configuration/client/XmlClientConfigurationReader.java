package org.owasp.appsensor.configuration.client;

import java.io.IOException;
import java.io.InputStream;
import java.text.ParseException;

import javax.xml.XMLConstants;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.Unmarshaller;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

public class XmlClientConfigurationReader implements ClientConfigurationReader {
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public ClientConfiguration read() throws ParseException {
		String defaultXmlLocation = "/appsensor-client-config.xml";
		String defaultXsdLocation = "/appsensor_client_config_2.0.xsd";
		
		return read(defaultXmlLocation, defaultXsdLocation);
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public ClientConfiguration read(String configurationLocation, String validatorLocation) throws ParseException {
		ClientConfiguration configuration = readConfiguration(configurationLocation, validatorLocation);
		
		return configuration;
	}
	
	private ClientConfiguration readConfiguration(String xml, String xsd) throws ParseException {
		ClientConfiguration configuration = new ReferenceJaxbClientConfiguration();
		
		InputStream xsdStream = null;
		InputStream xmlStream = null;
		
		try {
			xsdStream = getClass().getResourceAsStream(xsd);
			xmlStream = getClass().getResourceAsStream(xml);

			JAXBContext jaxbContext = JAXBContext.newInstance(ReferenceJaxbClientConfiguration.class);
			Unmarshaller unMarshaller = jaxbContext.createUnmarshaller();

			//do validation
			Schema schema = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI).newSchema(new StreamSource(xsdStream));
			unMarshaller.setSchema(schema);
			
			// unmarshal xml -> java
			configuration = (ClientConfiguration) unMarshaller.unmarshal(xmlStream);
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
