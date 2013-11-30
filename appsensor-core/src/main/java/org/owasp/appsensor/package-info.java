/**
 * This package declaration is used to associate the namespace for helping moxy do the xml binding. 
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
//TODO: this should be able to be removed
@javax.xml.bind.annotation.XmlSchema(namespace = "https://www.owasp.org/index.php/OWASP_AppSensor_Project/xsd/appsensor_server_config_2.0.xsd", elementFormDefault = javax.xml.bind.annotation.XmlNsForm.QUALIFIED)
package org.owasp.appsensor;
