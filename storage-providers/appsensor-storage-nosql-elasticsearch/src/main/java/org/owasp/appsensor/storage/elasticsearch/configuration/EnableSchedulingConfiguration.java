package org.owasp.appsensor.storage.elasticsearch.configuration;

import org.owasp.appsensor.storage.elasticsearch.dao.AbstractElasticRepository;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * This spring configuration class enables scheduling (cron tasks).
 * Scheduling is necessary for the case in which "appsensor.elasticsearch.rotatingindex" is configured to true.
 * Also see {@link AbstractElasticRepository#updateIndex()}
 *
 * @author Maik Jäkel(m.jaekel@xsite.de) http://www.xsite.de
 */
@EnableScheduling
@Configuration
public class EnableSchedulingConfiguration{

}