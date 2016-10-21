package org.owasp.appsensor.analysis;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.Queue;

import javax.inject.Inject;
import javax.inject.Named;

import org.joda.time.DateTime;
import org.owasp.appsensor.core.AppSensorServer;
import org.owasp.appsensor.core.Attack;
import org.owasp.appsensor.core.DetectionPoint;
import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.Interval;
import org.owasp.appsensor.core.Threshold;
import org.owasp.appsensor.core.User;
import org.owasp.appsensor.core.analysis.EventAnalysisEngine;
import org.owasp.appsensor.core.criteria.SearchCriteria;
import org.owasp.appsensor.core.logging.Loggable;
import org.owasp.appsensor.core.storage.EventStore;
import org.owasp.appsensor.core.util.DateUtils;
import org.slf4j.Logger;

/**
 * This is a rule based {@link Event} analysis engine.
 *
 * @author David Scrobonia (davidscrobonia@gmail.com)
 */
@Named
@Loggable
public class AggregateEventAnalysisEngine extends EventAnalysisEngine {

	private Logger logger;

	private ArrayList<Rule> rules;

	@Inject
	private AppSensorServer appSensorServer;

	/**
	 * This method determines whether an {@link Event} that has been added to the system
	 * has triggered a {@link Rule}. If so, an {@link Attack} is
	 * created and added to the system.
	 *
	 * @param event the {@link Event} that was added to the {@link EventStore}
	 */
	@Override
	public void analyze(Event triggerEvent) {
		Collection<Rule> appRules = getApplicableRules(triggerEvent);

		for (Rule rule : appRules) {
			if (checkRule(triggerEvent, rule)) {
				generateAttack(triggerEvent, rule);
			}
		}
	}

	public boolean checkRule(Event event, Rule rule) {
		Queue<TriggeredSensor> triggeredSensors = getTriggeredSensors(event, rule);
		Queue<TriggeredSensor> windowSensors = new LinkedList<TriggeredSensor>();
		Iterator<Expression> expressions = rule.getExpressions().iterator();
		Expression currentExpression = expressions.next();

		while (!triggeredSensors.isEmpty()) {
			TriggeredSensor tail = triggeredSensors.poll();
			windowSensors.add(tail);
			trim(windowSensors, tail.getEndTime().minus(currentExpression.getWindow().getDuration()));

			if (checkExpression(currentExpression, windowSensors)) {
				if (expressions.hasNext()) {
					currentExpression = expressions.next();
					windowSensors = new LinkedList<TriggeredSensor>();
					trim(triggeredSensors, tail.getEndTime());
				}
				else {
					return true;
				}
			}
		}

		return false;
	}

	public boolean checkExpression(Expression expression, Queue<TriggeredSensor> windowSensors) {
		for (Clause clause : expression.getClauses()) {
			if (checkClause(clause, windowSensors)) {
				return true;
			}
		}
		return false;
	}

	public boolean checkClause(Clause clause, Queue<TriggeredSensor> windowSensors) {
		Collection<DetectionPoint> windowDetectionPoints = new ArrayList<DetectionPoint>();

		for (TriggeredSensor triggeredSensor : windowSensors) {
			windowDetectionPoints.add(triggeredSensor.getDetectionPoint());
		}

		for (DetectionPoint detectionPoint : clause.getDetectionPoints()) {
			if (!windowDetectionPoints.contains(detectionPoint)) {
				return false;
			}
		}

		return true;
	}

	// todo: is is it better return new queue?
	public void trim(Queue<TriggeredSensor> triggeredSensors, DateTime time) {
		while (triggeredSensors.peek().getStartTime().isBefore(time)) {
			triggeredSensors.poll();
		}
	}

	public LinkedList<TriggeredSensor> getTriggeredSensors(Event triggerEvent, Rule rule) {
		LinkedList<TriggeredSensor> triggeredSensorQueue = new LinkedList<TriggeredSensor>();
		Collection<Event> events = getApplicableEvents(triggerEvent, rule);
		Collection<DetectionPoint> detectionPoints = rule.getAllDetectionPoints();

		for (DetectionPoint detectionPoint : detectionPoints) {
			Queue<Event> eventQueue = new LinkedList<Event>();

			for (Event event : events) {
				if (event.getDetectionPoint().typeAndThresholdMatches(detectionPoint)) {
					eventQueue.add(event);

					if (isThresholdViolated(eventQueue, detectionPoint.getThreshold(), event)) {
						int queueDuration = (int)getQueueInterval(eventQueue, event).toMillis();
						DateTime start = DateUtils.fromString(eventQueue.peek().getTimestamp());

						TriggeredSensor triggeredSensor = new TriggeredSensor(queueDuration, "milliseconds", start, detectionPoint);
						triggeredSensorQueue.add(triggeredSensor);
					}

					eventQueue.poll();
				}
			}
		}

		Collections.sort(triggeredSensorQueue, new TriggeredSensorComparator());

		return triggeredSensorQueue;
	}

	public Interval getQueueInterval(Queue<Event> queue, Event tailEvent) {
		DateTime endTime = DateUtils.fromString(tailEvent.getTimestamp());
		DateTime startTime = DateUtils.fromString(queue.peek().getTimestamp());

		return new Interval((int)endTime.minus(startTime.getMillis()).getMillis(), "milliseconds");
	}

	public boolean isThresholdViolated(Queue<Event> queue, Threshold threshold, Event tailEvent) {
		if (queue.size() >= threshold.getCount()) {

			Interval queueInterval = getQueueInterval(queue, tailEvent);

			if (queueInterval.toMillis() <= threshold.getInterval().toMillis()) {
				return true;
			}
		}

		return false;
	}

	public void generateAttack(Event event, Rule rule) {
		logger.info("Violation Observed for user <" + event.getUser().getUsername() + "> on rule <" + rule.getName() + "> - storing attack");

		Attack attack = new Attack();
		// todo: hack to make attack from a rule. Add an "R" to the end of the user
		attack.setUser(new User(event.getUser().getUsername() + "R"));
		attack.setRule(rule.getName());
		attack.setTimestamp(event.getTimestamp());
		attack.setDetectionPoint(event.getDetectionPoint());
		attack.setDetectionSystem(event.getDetectionSystem());
		attack.setResource(event.getResource());

		appSensorServer.getAttackStore().addAttack(attack);
	}

	protected ArrayList<Rule> getApplicableRules(Event event) {
		ArrayList<Rule> matches = new ArrayList<Rule>();

		for (Rule rule : rules) {
			if (rule.checkLastExpressionForDetectionPoint(event.getDetectionPoint())) {
				matches.add(rule);
			}
		}

		return matches;
	}

	protected ArrayList<Event> getApplicableEvents(Event triggerEvent, Rule rule) {
		ArrayList<Event> events = new ArrayList<Event>();

		SearchCriteria criteria = new SearchCriteria().
				setUser(triggerEvent.getUser()).
				setEarliest(findMostRecentAttackTime(triggerEvent, rule).plus(1).toString());

		for (DetectionPoint detectionPoint : rule.getAllDetectionPoints()) {
			criteria.
				setDetectionPoint(new DetectionPoint(detectionPoint.getCategory(), detectionPoint.getLabel())).
				setDetectionSystemIds(appSensorServer.getConfiguration().getRelatedDetectionSystems(triggerEvent.getDetectionSystem()));

			for (Event event : appSensorServer.getEventStore().findEvents(criteria)) {
				if (events.contains(event) == false) {
					events.add(event);
				}
			}
		}

		Collections.sort(events, new EventComparator());

		return events;
	}

	// TODO: will be changed one hack gets fixed
	// borrowed and tweaked from the Reference implementation
	protected DateTime findMostRecentAttackTime(Event event, Rule rule) {
		DateTime newest = DateUtils.epoch();

		// current hack around lack of support around rules adds "R" to the end of the user
		SearchCriteria criteria = new SearchCriteria().
				setUser(new User(event.getUser().getUsername() + "R")).
				setDetectionSystemIds(appSensorServer.getConfiguration().getRelatedDetectionSystems(event.getDetectionSystem()));

		Collection<Attack> attacks = appSensorServer.getAttackStore().findAttacks(criteria);

		for (Attack attack : attacks) {
			if (attack.getRule() != null && attack.getRule().equals(rule.getName())) {
				if (DateUtils.fromString(attack.getTimestamp()).isAfter(newest)) {
					newest = DateUtils.fromString(attack.getTimestamp());
				}
			}
		}

		return newest;
	}

	public void addRule(Rule rule) {
		if (rules == null) {
			rules = new ArrayList<Rule>();
		}
		rules.add(rule);
		logger.debug("Adding rule. Exps: " + rule.getExpressions().size() + " DPs: " + rule.getAllDetectionPoints().size());
		logger.debug("Total rules: " + rules.size());
	}

	public void removeRule(Rule rule) {
		if (rules != null) {
			rules.remove(rule);
		}
	}

	public void clearRules() {
		if (rules != null) {
			rules.clear();
			logger.debug("Clearing rules. Number of rules: " + rules.size());
		}
	}

	protected class EventComparator implements Comparator<Event> {

		public int compare(Event e1, Event e2) {
			if (DateUtils.fromString(e1.getTimestamp()).isBefore(DateUtils.fromString(e2.getTimestamp()))) {
				return -1;
			}
			else if (DateUtils.fromString(e1.getTimestamp()).isAfter(DateUtils.fromString(e2.getTimestamp()))) {
				return 1;
			}
			else {
				return 0;
			}
		}
	}

	protected class TriggeredSensorComparator implements Comparator<TriggeredSensor> {
		public int compare(TriggeredSensor ts1, TriggeredSensor ts2) {
			if (ts1.getStartTime().isBefore(ts2.getStartTime())) {
				return -1;
			}
			else if (ts1.getStartTime().isAfter(ts2.getStartTime())) {
				return 1;
			}
			else {
				return 0;
			}
		}
	}
}
