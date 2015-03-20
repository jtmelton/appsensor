package org.owasp.appsensor.integration.cef.syslog;

import java.nio.charset.StandardCharsets;

import javax.inject.Named;

import org.owasp.appsensor.core.Attack;
import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.Response;
import org.owasp.appsensor.core.listener.SystemListener;
import org.owasp.appsensor.core.logging.Loggable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * <p>This is an emitter that output CEF over syslog. </p> 
 * 
 * <p>It is notified whenever new {@link Event}, {@link Attack} 
 * or {@link Response} objects are added to the system. </p> 
 * 
 * <p>The implementation creates CEF events over the syslog transport. 
 * This can be used to integrate with various different systems.</p>
 *  
 * <p>Look at the logback.xml config file in the src/test/resources folder
 * for an example of how to configure the system.</p> 
 * 
 * <p>You need a logger named "appsensor_syslog", which is the name 
 * looked up in the emitter to write to. The appender should be of type: 
 * {@link com.papertrailapp.logback.Syslog4jAppender}.</p>
 * 
 * <p>In configuration, you can set it up to use any of the following 
 * protocols: [UDP, TCP, TCP with TLS] </p>
 * 
 * @see <a href="https://github.com/papertrail/logback-syslog4j">papertrail syslog4j logback wrapper</a>
 * @see <a href="http://syslog4j.org/">syslog4j library</a>
 * @see <a href="https://protect724.hp.com/docs/DOC-1072">latest CEF documentation</a>
 * @see <a href="https://protect724.hp.com/servlet/JiveServlet/downloadBody/1072-102-6-4697/CommonEventFormat.pdf">CEF documentation used at time of writing (2015/03/20)</a>
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 * 
 * @since 2.1
 * 
 */
@Named
@Loggable
public class CefSyslogEmitter extends SystemListener {
	
	Logger syslog = LoggerFactory.getLogger("appsensor_syslog");

	private static final String SYSLOG_FIELD_DELIMETER = "|";
	private static final String SPACE = " ";
	
	private Logger logger;
	
	public CefSyslogEmitter() {}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void onAdd(Event event) {
		logger.info("Security event " + event.getDetectionPoint().getLabel() + " triggered by user: " + event.getUser().getUsername());
		syslog.info(toCef(event));
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void onAdd(Attack attack) {
		logger.info("Security attack " + attack.getDetectionPoint().getLabel() + " triggered by user: " + attack.getUser().getUsername());
		syslog.info(toCef(attack));
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void onAdd(Response response) {
		logger.info("Security response " + response.getAction() + " created for user: " + response.getUser().getUsername());
		syslog.info(toCef(response));
	}
	
	protected String toCef(Event event) {
		StringBuilder sb = new StringBuilder();
		
		// HEADERS
		// --------------
		
		// timestamp and host are handled automatically
		
		// CEF:Version
		sb.append("CEF:0");
		sb.append(SYSLOG_FIELD_DELIMETER);
		
		// Device Vendor
		sb.append("OWASP");
		sb.append(SYSLOG_FIELD_DELIMETER);
		
		// Device Product
		sb.append("appsensor");
		sb.append(SYSLOG_FIELD_DELIMETER);

		// Device Version
		sb.append("1.0");	//hardcode
		sb.append(SYSLOG_FIELD_DELIMETER);

		// Signature ID
		sb.append(encodeCEFHeader(event.getDetectionPoint().getLabel()));
		sb.append(SYSLOG_FIELD_DELIMETER);
		
		// Name
		sb.append(encodeCEFHeader(event.getDetectionPoint().getCategory()));
		sb.append(SYSLOG_FIELD_DELIMETER);
		
		// Severity
		sb.append("3");		//no matching severity in appsensor - hardcode 3 (event)
		sb.append(SYSLOG_FIELD_DELIMETER);
		
		// EXTENSIONS
		// --------------
		
		// category 
		sb.append("cat=event_detection");
		sb.append(SPACE);

		if (event.getResource() != null && event.getResource().getLocation() != null) {
			// resource location
			sb.append("cs1Label=resourceLocation");
			sb.append(SPACE);
			sb.append("cs1=");
			sb.append(encodeCEFExtension(event.getResource().getLocation()));
			sb.append(SPACE);
		}
		
		// detection system
		sb.append("deviceExternalId=");
		sb.append(encodeCEFExtension(event.getDetectionSystem().getDetectionSystemId()));
		sb.append(SPACE);
		
		// source ip (if available)
		if (event.getUser().getIPAddress() != null && event.getUser().getIPAddress().getAddressAsString() != null) {
			sb.append("src=");
			sb.append(encodeCEFExtension(event.getUser().getIPAddress().getAddressAsString()));
			sb.append(SPACE);
		}
				
		// destination ip (if available)
		if (event.getDetectionSystem().getIPAddress() != null && event.getDetectionSystem().getIPAddress().getAddressAsString() != null) {
			sb.append("dst=");
			sb.append(encodeCEFExtension(event.getDetectionSystem().getIPAddress().getAddressAsString()));
			sb.append(SPACE);
		}
		
		// user
		sb.append("suser=");
		sb.append(encodeCEFExtension(event.getUser().getUsername()));
		sb.append(SPACE);
		
		if (event.getResource() != null && event.getResource().getLocation() != null) {
			// request
			sb.append("request=");
			sb.append(encodeCEFExtension(event.getResource().getLocation()));
			sb.append(SPACE);
		}
		
		// return must be in UTF-8 for syslog 
		byte[] bytes = sb.toString().getBytes(StandardCharsets.UTF_8);
		return new String(bytes, StandardCharsets.UTF_8);
	}
	
	protected String toCef(Attack attack) {
		StringBuilder sb = new StringBuilder();
		
		// HEADERS
		// --------------
		
		// timestamp and host are handled automatically
		
		// CEF:Version
		sb.append("CEF:0");
		sb.append(SYSLOG_FIELD_DELIMETER);
		
		// Device Vendor
		sb.append("OWASP");
		sb.append(SYSLOG_FIELD_DELIMETER);
		
		// Device Product
		sb.append("appsensor");
		sb.append(SYSLOG_FIELD_DELIMETER);

		// Device Version
		sb.append("1.0");	//hardcode
		sb.append(SYSLOG_FIELD_DELIMETER);

		// Signature ID
		sb.append(encodeCEFHeader(attack.getDetectionPoint().getLabel()));
		sb.append(SYSLOG_FIELD_DELIMETER);
		
		// Name
		sb.append(encodeCEFHeader(attack.getDetectionPoint().getCategory()));
		sb.append(SYSLOG_FIELD_DELIMETER);
		
		// Severity
		sb.append("7");		//no matching severity in appsensor - hardcode 7 (attack)
		sb.append(SYSLOG_FIELD_DELIMETER);
		
		// EXTENSIONS
		// --------------
		
		// category 
		sb.append("cat=attack_detection");
		sb.append(SPACE);

		if (attack.getResource() != null && attack.getResource().getLocation() != null) {
			// resource location
			sb.append("cs1Label=resourceLocation");
			sb.append(SPACE);
			sb.append("cs1=");
			sb.append(encodeCEFExtension(attack.getResource().getLocation()));
			sb.append(SPACE);
		}
		
		// detection system
		sb.append("deviceExternalId=");
		sb.append(encodeCEFExtension(attack.getDetectionSystem().getDetectionSystemId()));
		sb.append(SPACE);
		
		// source ip (if available)
		if (attack.getUser().getIPAddress() != null && attack.getUser().getIPAddress().getAddressAsString() != null) {
			sb.append("src=");
			sb.append(encodeCEFExtension(attack.getUser().getIPAddress().getAddressAsString()));
			sb.append(SPACE);
		}
				
		// destination ip (if available)
		if (attack.getDetectionSystem().getIPAddress() != null && attack.getDetectionSystem().getIPAddress().getAddressAsString() != null) {
			sb.append("dst=");
			sb.append(encodeCEFExtension(attack.getDetectionSystem().getIPAddress().getAddressAsString()));
			sb.append(SPACE);
		}
		
		// user
		sb.append("suser=");
		sb.append(encodeCEFExtension(attack.getUser().getUsername()));
		sb.append(SPACE);
		
		if (attack.getResource() != null && attack.getResource().getLocation() != null) {
			// request
			sb.append("request=");
			sb.append(encodeCEFExtension(attack.getResource().getLocation()));
			sb.append(SPACE);
		}
		
		// threshold count
		sb.append("cn1Label=thresholdCount");
		sb.append(SPACE);
		sb.append("cn1=");
		sb.append(encodeCEFExtension(attack.getDetectionPoint().getThreshold().getCount()));
		sb.append(SPACE);
		
		// interval duration
		sb.append("cn2Label=intervalDuration");
		sb.append(SPACE);
		sb.append("cn2=");
		sb.append(encodeCEFExtension(attack.getDetectionPoint().getThreshold().getInterval().getDuration()));
		sb.append(SPACE);

		// interval duration
		sb.append("cs1Label=intervalUnit");
		sb.append(SPACE);
		sb.append("cs1=");
		sb.append(encodeCEFExtension(attack.getDetectionPoint().getThreshold().getInterval().getUnit()));
		sb.append(SPACE);

		// return must be in UTF-8 for syslog 
		byte[] bytes = sb.toString().getBytes(StandardCharsets.UTF_8);
		return new String(bytes, StandardCharsets.UTF_8);
	}
	
	protected String toCef(Response response) {
		StringBuilder sb = new StringBuilder();
		
		// HEADERS
		// --------------
		
		// timestamp and host are handled automatically
		
		// CEF:Version
		sb.append("CEF:0");
		sb.append(SYSLOG_FIELD_DELIMETER);
		
		// Device Vendor
		sb.append("OWASP");
		sb.append(SYSLOG_FIELD_DELIMETER);
		
		// Device Product
		sb.append("appsensor");
		sb.append(SYSLOG_FIELD_DELIMETER);

		// Device Version
		sb.append("1.0");	//hardcode
		sb.append(SYSLOG_FIELD_DELIMETER);

		// Signature ID
		sb.append(encodeCEFHeader(response.getAction()));
		sb.append(SYSLOG_FIELD_DELIMETER);
		
		// Name
		sb.append(encodeCEFHeader("appsensor_response"));
		sb.append(SYSLOG_FIELD_DELIMETER);
		
		// Severity
		sb.append("7");		//no matching severity in appsensor - hardcode 7 (attack)
		sb.append(SYSLOG_FIELD_DELIMETER);
		
		// EXTENSIONS
		// --------------
		
		// category 
		sb.append("cat=response_creation");
		sb.append(SPACE);

		// r
		sb.append("act=");
		sb.append(encodeCEFExtension(response.getAction()));
		sb.append(SPACE);
				
		// detection system
		sb.append("deviceExternalId=");
		sb.append(encodeCEFExtension(response.getDetectionSystem().getDetectionSystemId()));
		sb.append(SPACE);
		
		// destination ip (if available) [destination is user in case of response]
		if (response.getUser().getIPAddress() != null && response.getUser().getIPAddress().getAddressAsString() != null) {
			sb.append("dst=");
			sb.append(encodeCEFExtension(response.getUser().getIPAddress().getAddressAsString()));
			sb.append(SPACE);
		}
				
		// source ip (if available)	[source is detection system in case of response]
		if (response.getDetectionSystem().getIPAddress() != null && response.getDetectionSystem().getIPAddress().getAddressAsString() != null) {
			sb.append("src=");
			sb.append(encodeCEFExtension(response.getDetectionSystem().getIPAddress().getAddressAsString()));
			sb.append(SPACE);
		}
		
		// user
		sb.append("suser=");
		sb.append(encodeCEFExtension(response.getUser().getUsername()));
		sb.append(SPACE);
		
		if(response.getInterval() != null) {
			// interval duration
			sb.append("cn1Label=intervalDuration");
			sb.append(SPACE);
			sb.append("cn1=");
			sb.append(encodeCEFExtension(response.getInterval().getDuration()));
			sb.append(SPACE);
	
			// interval duration
			sb.append("cs1Label=intervalUnit");
			sb.append(SPACE);
			sb.append("cs1=");
			sb.append(encodeCEFExtension(response.getInterval().getUnit()));
			sb.append(SPACE);
		}
		
		// return must be in UTF-8 for syslog 
		byte[] bytes = sb.toString().getBytes(StandardCharsets.UTF_8);
		return new String(bytes, StandardCharsets.UTF_8);
	}
	
	// encoder for CEF header format
	// header needs to encode '|', '\' '\r', '\n'
	protected String encodeCEFHeader(String text) {
		String encoded = text;
		
		// back-slash encode back-slashes (needs to be first)
		encoded = encoded.replace("\\","\\\\");
		
		// back-slash encode pipes
		encoded = encoded.replace("|","\\|");
		
		// strip carriage returns and newlines
		encoded = encoded.replace("\r", "");
		encoded = encoded.replace("\n", "");
				
		return encoded;
	}
		
	// encoder for CEF extension format
	// extension needs to encode '\', '=' '\r', '\n'
	protected String encodeCEFExtension(String text) {
		String encoded = text;
		
		// back-slash encode back-slashes (needs to be first)
		encoded = encoded.replace("\\","\\\\");
		
		// back-slash encode equals signs
		encoded = encoded.replace("=","\\=");
		
		// strip carriage returns and newlines
		encoded = encoded.replace("\r", "");
		encoded = encoded.replace("\n", "");
		
		return encoded;
	}
	
	// just so everything can "encode", even though
	// ints don't need it
	protected int encodeCEFExtension(int value) {
		return value;
	}

}
