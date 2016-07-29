package org.owasp.appsensor.storage.elasticsearch.mapping;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.Version;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.datatype.hibernate5.Hibernate5Module;
import org.owasp.appsensor.core.geolocation.GeoLocation;

/**
 * This is a class to serialize objects to elastic search in the same way as the jpa implementation would do it
 *
 * @author Maik Jäkel(m.jaekel@xsite.de) http://www.xsite.de
 */
public class ElasticSearchJsonMapper extends ObjectMapper {

    public ElasticSearchJsonMapper() {


        SimpleModule customSerializationModule = new SimpleModule("AppSensorElasticSearch", new Version(1, 0, 0, null));

        customSerializationModule.addSerializer(GeoLocation.class, new GeoLocationMapperSerializer());
        customSerializationModule.addDeserializer(GeoLocation.class, new GeoLocationMapperDeSerializer());

        this.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        this.setSerializationInclusion(JsonInclude.Include.NON_NULL);

        this.registerModule(new Hibernate5Module());
        this.registerModule(customSerializationModule);
    }

}
