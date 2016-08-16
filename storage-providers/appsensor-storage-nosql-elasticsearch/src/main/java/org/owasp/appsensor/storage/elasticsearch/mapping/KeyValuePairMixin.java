package org.owasp.appsensor.storage.elasticsearch.mapping;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import org.owasp.appsensor.core.KeyValuePair;

import java.util.Collection;

/**
 * Jackson Mixin to serialize / deserialize KeyValuePair collections as JSON maps
 * The mixin is necessary, as a direct replacement of the structure in the java classes from Collection<KeyValuePair> to
 * Map<String, String> would break backwards compatibility.
 *
 * @author Maik Jäkel(m.jaekel@xsite.de) http://www.xsite.de
 */
abstract class KeyValuePairMixin {

    @JsonProperty("metadata")
    @JsonSerialize(using = KeyValuePairCollectionSerializer.class)
    abstract void setMetadata(Collection<KeyValuePair> metadata);

    @JsonProperty("metadata")
    @JsonDeserialize(using = KeyValuePairCollectionDeserializer.class)
    abstract Collection<KeyValuePair> getMetadata();

}
