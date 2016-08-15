package org.owasp.appsensor.storage.elasticsearch.mapping;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import org.owasp.appsensor.core.KeyValuePair;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;

/**
 * Jackson Deserializer that deserializes from a conventional JSON map to Collection<KeyValuePair>.
 *
 * @author Maik Jäkel(m.jaekel@xsite.de) http://www.xsite.de
 */
class KeyValuePairCollectionDeserializer extends JsonDeserializer<Collection<KeyValuePair>> {

    @Override
    public Collection<KeyValuePair> deserialize(JsonParser jsonParser, DeserializationContext ctxt) throws IOException, JsonProcessingException {

        JsonToken jsonToken;
        Collection<KeyValuePair> resultCollection = new ArrayList<>();

        while ((jsonToken = jsonParser.nextValue()) != null) {

            switch (jsonToken) {
                case VALUE_STRING:
                    resultCollection.add(new KeyValuePair(jsonParser.getCurrentName(), jsonParser.getValueAsString()));
                    break;
                default:
                    break;
            }
        }

        return resultCollection;
    }
}
