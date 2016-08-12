package org.owasp.appsensor.storage.elasticsearch.mapping;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import org.owasp.appsensor.core.geolocation.GeoLocation;

import java.io.IOException;

/**
 * Created by jaekel on 18.07.16.
 */
public class GeoLocationMapperSerializer extends StdSerializer<GeoLocation> {
    public GeoLocationMapperSerializer() {
        super(GeoLocation.class);
    }

    @Override
    public void serialize(GeoLocation geoLocation, JsonGenerator jgen, SerializerProvider serializerProvider) throws IOException {

        jgen.writeStartObject();
        jgen.writeNumberField("lat", geoLocation.getLatitude());
        jgen.writeNumberField("lon", geoLocation.getLongitude());

        jgen.writeEndObject();
    }
}
