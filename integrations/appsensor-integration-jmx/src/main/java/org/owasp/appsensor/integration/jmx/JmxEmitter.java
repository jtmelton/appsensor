package org.owasp.appsensor.integration.jmx;

import java.lang.management.ManagementFactory;

import javax.annotation.PostConstruct;
import javax.inject.Named;
import javax.management.InstanceAlreadyExistsException;
import javax.management.MBeanRegistrationException;
import javax.management.MBeanServer;
import javax.management.NotCompliantMBeanException;
import javax.management.Notification;
import javax.management.NotificationBroadcasterSupport;
import javax.management.NotificationListener;
import javax.management.ObjectName;

import org.owasp.appsensor.core.Attack;
import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.Response;
import org.owasp.appsensor.core.listener.SystemListener;
import org.owasp.appsensor.core.logging.Loggable;
import org.slf4j.Logger;

import com.google.gson.Gson;

/**
 * This is the JMX Emitter. 
 * 
 * It is notified whenever new {@link Event}, {@link Attack} 
 * or {@link Response} objects are added to the system. 
 * 
 * The implementation creates JMX notifications. These can 
 * be subscribed to by a number of mechanisms. You can 
 * create a JMX {@link NotificationListener} if you want 
 * to do something programmatically. If you'd like to just see 
 * the notifications for testing purposes, you can use the 
 * jconsole tool, and subscribe to notifications for the 
 * following object names:
 * 
 * <ul>
 * 	<li>org.owasp.appsensor.metrics:service=JxmReporting,name=Event</li>
 * 	<li>org.owasp.appsensor.metrics:service=JxmReporting,name=Attack</li>
 *  <li>org.owasp.appsensor.metrics:service=JxmReporting,name=Response</li>
 * </ul>
 * 
 * In order to see these notifications, use your standard 
 * JMX notification mechanisms/tools and register to the notifications
 * for the above object names
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 * 
 * @since 2.1
 * 
 */
@Named
@Loggable
public class JmxEmitter extends SystemListener {
	
	@SuppressWarnings("unused")
	private Logger logger;
	
	private static MBeanServer mBeanServer;
	
	private static Gson gson = new Gson();
	
	private JmxEvent jmxEvent = null;
	private JmxAttack jmxAttack = null;
	private JmxResponse jmxResponse = null;
	
	private ObjectName eventName;
	private ObjectName attackName;
	private ObjectName responseName;
	
	public JmxEmitter() {}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void onAdd(Event event) {
		jmxEvent.add(event);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void onAdd(Attack attack) {
		jmxAttack.add(attack);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void onAdd(Response response) {
		jmxResponse.add(response);
	}
	
	@PostConstruct
	public void initializeJmx() {
		if (mBeanServer==null) {
        	mBeanServer = ManagementFactory.getPlatformMBeanServer();
        }
		
		eventName = createName("Event");
		attackName = createName("Attack");
		responseName = createName("Response");
		
		jmxEvent = new JmxEvent();
		jmxAttack = new JmxAttack();
		jmxResponse = new JmxResponse();
	}
    
	protected ObjectName createName(String name) {
		ObjectName oName = null;
		
		try {
			oName = new ObjectName("org.owasp.appsensor.metrics:service=JxmReporting,name=" + name);
		} catch(Exception e) {
			//
		}
		
		return oName;
	}
	
	// for debugging the following listener can be uncommented along with the 
	// addNotificationListener calls below for [event, attack, response]
//	private NotificationListener consoleNotificationListener = new NotificationListener() {
//		@Override
//		public void handleNotification(Notification notification, Object handback) {
//			System.out.println("*** Handling new notification ***");
//			System.out.println("Type: " + notification.getType());
//			System.out.println("Message: " + notification.getMessage());
//			System.out.println("Seq: " + notification.getSequenceNumber());
//			System.out.println("*********************************");
//		}
//	};
	
	public interface JmxAppSensorMBean {}
	public interface JmxEventMBean extends JmxAppSensorMBean {}
	public interface JmxAttackMBean extends JmxAppSensorMBean {}
	public interface JmxResponseMBean extends JmxAppSensorMBean {}

	private class Notifier extends NotificationBroadcasterSupport {
		protected void registerMBean(JmxAppSensorMBean mBean, ObjectName objectName) {
			try {
				mBeanServer.registerMBean(mBean, objectName);
			} catch (InstanceAlreadyExistsException | MBeanRegistrationException | NotCompliantMBeanException e) {
				e.printStackTrace();
			}
		}
	}
	
    private class JmxEvent extends Notifier implements JmxEventMBean {
        
    	// sequence number for notifications 
    	private long notificationSequence = 0;
    	
        private JmxEvent() {
//            addNotificationListener(consoleNotificationListener, null, null);
    		registerMBean(this, eventName);
        }
        
        public void add(Event event) {
			sendNotification(
					new Notification("org.owasp.appsensor.jmxnotifications.event.add", // type
							this, // source
							++notificationSequence, // seq. number
							gson.toJson(event)	//message
			));
        }
    }
    
    private class JmxAttack extends Notifier implements JmxAttackMBean {
        
    	// sequence number for notifications 
    	private long notificationSequence = 0;
    	
        private JmxAttack() {
//        	addNotificationListener(consoleNotificationListener, null, null);
    		registerMBean(this, attackName);
        }
        
        public void add(Attack attack) {
			sendNotification(
					new Notification("org.owasp.appsensor.jmxnotifications.attack.add", // type
							this, // source
							++notificationSequence, // seq. number
							gson.toJson(attack)	//message
			));
        }
    }

	private class JmxResponse extends Notifier implements JmxResponseMBean {
	    
		// sequence number for notifications 
    	private long notificationSequence = 0;
    	
	    private JmxResponse() {
//	        addNotificationListener(consoleNotificationListener, null, null);
    		registerMBean(this, responseName);
	    }
	    
	    public void add(Response response) {
			sendNotification(
					new Notification("org.owasp.appsensor.jmxnotifications.response.add", // type
							this, // source
							++notificationSequence, // seq. number
							gson.toJson(response)	//message
			));
        }
	}
	
	
}
