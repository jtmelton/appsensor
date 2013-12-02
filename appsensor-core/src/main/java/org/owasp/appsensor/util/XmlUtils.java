package org.owasp.appsensor.util;

import java.io.IOException;
import java.io.InputStream;
import java.util.Map;

import javax.xml.XMLConstants;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;

import org.xml.sax.SAXException;

public class XmlUtils {
	
	public static void validateXMLSchema(String xsdPath, String xmlPath) throws IOException, SAXException {
		InputStream xsdStream = XmlUtils.class.getResourceAsStream(xsdPath);
		InputStream xmlStream = XmlUtils.class.getResourceAsStream(xmlPath);
		
		validateXMLSchema(xsdStream, xmlStream);
    }
	
	public static void validateXMLSchema(InputStream xsdStream, InputStream xmlStream) throws IOException, SAXException {
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        Schema schema = factory.newSchema(new StreamSource(xsdStream));
        Validator validator = schema.newValidator();
        validator.validate(new StreamSource(xmlStream));
    }
	
	public static String getElementQualifiedName(XMLStreamReader xmlReader, Map<String, String> namespaces) {
		String namespaceUri = null;
		String localName = null;
		
		switch(xmlReader.getEventType()) {
			case XMLStreamConstants.START_ELEMENT:
			case XMLStreamConstants.END_ELEMENT:
				namespaceUri = xmlReader.getNamespaceURI();
				localName = xmlReader.getLocalName();
				break;
			default:
				localName = StringUtils.EMPTY;
				break;
		}
		
		return namespaces.get(namespaceUri) + ":" + localName;
	}
	
}
