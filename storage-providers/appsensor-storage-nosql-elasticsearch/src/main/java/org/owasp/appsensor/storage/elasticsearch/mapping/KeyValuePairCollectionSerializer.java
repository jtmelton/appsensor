package org.owasp.appsensor.storage.elasticsearch.mapping;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import org.owasp.appsensor.core.KeyValuePair;

import java.io.IOException;
import java.util.Collection;

/**
 * Jackson Serializer that serializes from Collection<KeyValuePair> to a convential JSON map.
 *
 * @author Maik Jäkel(m.jaekel@xsite.de) http://www.xsite.de
 */
class KeyValuePairCollectionSerializer extends JsonSerializer<Collection<KeyValuePair>>{
    @Override
    public void serialize(Collection<KeyValuePair> kvpCollection, JsonGenerator jgen, SerializerProvider serializers) throws IOException {
        jgen.writeStartObject();

        for(KeyValuePair kvp: kvpCollection){
            jgen.writeStringField(kvp.getKey(), kvp.getValue());
        }
        
        jgen.writeEndObject();
    }
}
