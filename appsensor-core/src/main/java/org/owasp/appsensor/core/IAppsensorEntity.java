package org.owasp.appsensor.core;

import java.io.Serializable;

/**
 * Interface denoting methods required to be provided by appsensor entity objects
 * @author Maik Jäkel(m.jaekel@xsite.de) http://www.xsite.de
 */
public interface IAppsensorEntity extends Serializable{

    String getId();

   void setId(String id);
}
