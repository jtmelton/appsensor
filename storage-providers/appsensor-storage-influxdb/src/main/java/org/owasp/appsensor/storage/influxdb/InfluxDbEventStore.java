package org.owasp.appsensor.storage.influxdb;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.TimeUnit;

import javax.annotation.PostConstruct;
import javax.inject.Inject;
import javax.inject.Named;

import org.influxdb.InfluxDB;
import org.influxdb.InfluxDBFactory;
import org.influxdb.dto.Point;
import org.influxdb.dto.Query;
import org.influxdb.dto.QueryResult;
import org.joda.time.DateTime;
import org.owasp.appsensor.core.DetectionPoint;
import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.User;
import org.owasp.appsensor.core.criteria.SearchCriteria;
import org.owasp.appsensor.core.listener.EventListener;
import org.owasp.appsensor.core.logging.Loggable;
import org.owasp.appsensor.core.rule.Rule;
import org.owasp.appsensor.core.storage.EventStore;
import org.owasp.appsensor.core.util.DateUtils;
import org.slf4j.Logger;
import org.springframework.core.env.Environment;

import com.google.common.base.Preconditions;
import com.google.gson.Gson;

/**
 * This is an influxdb implementation of the {@link EventStore}.
 *
 * Implementations of the {@link EventListener} interface can register with
 * this class and be notified when new {@link Event}s are added to the data store
 *
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 *
 */
@Named
@Loggable
public class InfluxDbEventStore extends EventStore {

  private Logger logger;

  private InfluxDB influxDB;

  private final Gson gson = new Gson();

  private boolean initializedProperly = true;

  @Inject
  private Environment environment;

  /**
   * {@inheritDoc}
   */
  @Override
  public void addEvent(Event event) {
    ensureInitialized();

    logger.warn("Security event " + event.getDetectionPoint().getLabel() + " triggered by user: " + event.getUser().getUsername());

    Point point = Point.measurement(Utils.EVENTS)
        .time(DateUtils.fromString(event.getTimestamp()).getMillis(), TimeUnit.MILLISECONDS)
        .field(Utils.LABEL, event.getDetectionPoint().getLabel())
        .tag(Utils.USERNAME, event.getUser().getUsername())
        .tag(Utils.TIMESTAMP, event.getTimestamp())
        .tag(Utils.DETECTION_SYSTEM, event.getDetectionSystem().getDetectionSystemId())
        .tag(Utils.CATEGORY, event.getDetectionPoint().getCategory())
        .tag(Utils.LABEL, event.getDetectionPoint().getLabel())
        .field(Utils.JSON_CONTENT, gson.toJson(event))
        .build();

    influxDB.write(Utils.DATABASE, "default", point);

    super.notifyListeners(event);
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public Collection<Event> findEvents(SearchCriteria criteria) {
    ensureInitialized();

    Preconditions.checkNotNull(criteria, "criteria must be non-null");

    Collection<Event> matches = new ArrayList<>();

    User user = criteria.getUser();
    DetectionPoint detectionPoint = criteria.getDetectionPoint();
    Rule rule = criteria.getRule();
    Collection<String> detectionSystemIds = criteria.getDetectionSystemIds();
    DateTime earliest = DateUtils.fromString(criteria.getEarliest());

    String influxQL = Utils.constructInfluxQL(Utils.EVENTS, user,
      detectionPoint, null,
      detectionSystemIds,
      earliest,
      Utils.QueryMode.IGNORE_THRESHOLDS);

    if (rule != null) {
      influxQL += " AND (";

      int i = 0;
      for (DetectionPoint point : rule.getAllDetectionPoints()) {
        influxQL += (i == 0) ? "" : " OR ";

        influxQL += "(";
        influxQL += Utils.constructDetectionPointSqlString(point, Utils.QueryMode.IGNORE_THRESHOLDS);
        influxQL += ")";

        i++;
      }

      influxQL += ")";
    }

    Query query = new Query(influxQL, Utils.DATABASE);

    QueryResult results = influxDB.query(query);

    for(QueryResult.Result result : results.getResults()) {
      if(result == null || result.getSeries() == null) {
        continue;
      }

      for(QueryResult.Series series : result.getSeries()) {
        if(series == null || series.getValues() == null) {
          continue;
        }

        for(List<Object> record : series.getValues()) {
          if(record == null) {
            continue;
          }

          matches.add( gson.fromJson( Utils.getValue(Utils.JSON_CONTENT, series, record), Event.class ) );
        }

      }
    }

    return matches;
  }

  private void ensureInitialized() {
    if(! initializedProperly) {
      throw new IllegalStateException(Utils.getUninitializedMessage(environment));
    }
  }

  @PostConstruct
  public void ensureEnvironmentVariablesSet() {
    initializedProperly = Utils.isInitializedProperly(environment);

    if(initializedProperly) {
      influxDB = InfluxDBFactory.connect(environment.getProperty(Utils.INFLUXDB_CONNECTION_STRING),
                                         environment.getProperty(Utils.INFLUXDB_USERNAME),
                                         environment.getProperty(Utils.INFLUXDB_PASSWORD));

      Utils.createDatabaseIfNotExists(influxDB);
    } else {
      String msg = Utils.getUninitializedMessage(environment);

      if(logger != null) {
        logger.error(msg);
      } else {
        System.err.println(msg);
      }
    }
  }

}