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
 * It is notified with implementations of the {@link Event} class.
 *
 * The implementation analyzes whether defined {@link Rule}s should generate an
 * {@link Attack} by determining whether the {@link Rule}'s boolean logic evaluates
 * to true.
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

	/**
	 * Evaluates a {@link Rule}'s boolean logic by compiling a list of all triggered sensors
	 * and then evaluating each {@link Expression} within the {@link Rule}. All {@link Expression}s
	 * evaluate to true within the {@link Rule}'s window for the {@link Rule} to evaluate to true.
	 * The process follows the "sliding window" pattern.
	 *
	 * @param event the {@link Event} that triggered analysis
	 * @param rule the {@link Rule} being evaluated
	 * @return the boolean evaluation of the {@link Rule}
	 */
	protected boolean checkRule(Event event, Rule rule) {
		Queue<TriggeredSensor> triggeredSensors = getTriggeredSensors(event, rule);
		Queue<TriggeredSensor> windowSensors = new LinkedList<TriggeredSensor>();
		Iterator<Expression> expressions = rule.getExpressions().iterator();
		Expression currentExpression = expressions.next();

		while (!triggeredSensors.isEmpty()) {
			TriggeredSensor tail = triggeredSensors.poll();
			windowSensors.add(tail);
			trim(windowSensors, tail.getEndTime().minus(currentExpression.getWindow().toMillis()));

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

	/**
	 * Evaluates an {@link Expression}'s boolean logic by evaluating all {@link Clause}s. Any
	 * {@link Clause} must evaluate to true for the {@link Expression} to evaluate to true.
	 *
	 * Equivalent to checking "OR" logic between {@link Clause}s.
	 *
	 * @param expression the {@link Expression} being evaluated
	 * @param windowSensors the {@link TriggeredSensor}s in the current "sliding window"
	 * @return the boolean evaluation of the {@link Expression}
	 */
	protected boolean checkExpression(Expression expression, Queue<TriggeredSensor> windowSensors) {
		for (Clause clause : expression.getClauses()) {
			if (checkClause(clause, windowSensors)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Evaluates a {@link Clause}'s boolean logic by checking if each {@link RulesDetectionPoint}
	 * within the {@link Clause} is in the current "sliding window".
	 *
	 * Equivalent to checking "AND" logic between {@link RuleDetectionPoint}s
	 *
	 * @param clause the {@link Clause} being evaluated
	 * @param windowSensors the {@link TriggeredSensor}s in the current "sliding window"
	 * @return the boolean evaluation of the {@link Clause}
	 */
	protected boolean checkClause(Clause clause, Queue<TriggeredSensor> windowSensors) {
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
	// toso: should i sort before just to be safe or assume its sorted?
	/**
	 * Pops {@link TriggeredSensor}s out of the queue until the start time of the queue's head
	 * is after the parameter time.
	 *
	 * @param triggeredSensors the queue of {@link TriggeredSensor}s being trimmed
	 * @param time the time that all {@link TriggeredSensor}s in the queue must be after
	 */
	protected void trim(Queue<TriggeredSensor> triggeredSensors, DateTime time) {
		while (!triggeredSensors.isEmpty() && !triggeredSensors.peek().getStartTime().isAfter(time)) {
			triggeredSensors.poll();
		}
	}

	/**
	 * Builds a queue of all {@link TriggeredSensors} from the events relating to the
	 * current {@link Rule}. The {@link TriggeredSensors} are ordered in the Queue by
	 * start time.
	 *
	 * @param triggerEvent the {@link Event} that triggered analysis
	 * @param rule the {@link Rule} being evaluated
	 * @return a queue of {@link TriggerEvents}
	 */
	protected LinkedList<TriggeredSensor> getTriggeredSensors(Event triggerEvent, Rule rule) {
		LinkedList<TriggeredSensor> triggeredSensorQueue = new LinkedList<TriggeredSensor>();
		Collection<Event> events = getApplicableEvents(triggerEvent, rule);
		Collection<DetectionPoint> detectionPoints = rule.getAllDetectionPoints();

		for (DetectionPoint detectionPoint : detectionPoints) {
			Queue<Event> eventQueue = new LinkedList<Event>();

			for (Event event : events) {
				if (event.getDetectionPoint().typeAndThresholdMatches(detectionPoint)) {
					eventQueue.add(event);

					if (isThresholdViolated(eventQueue, event, detectionPoint.getThreshold())) {
						int queueDuration = (int)getQueueInterval(eventQueue, event).toMillis();
						DateTime start = DateUtils.fromString(eventQueue.peek().getTimestamp());

						TriggeredSensor triggeredSensor = new TriggeredSensor(queueDuration, "milliseconds", start, detectionPoint);
						triggeredSensorQueue.add(triggeredSensor);
					}

					if (eventQueue.size() >= detectionPoint.getThreshold().getCount()) {
						eventQueue.poll();
					}
				}
			}
		}

		Collections.sort(triggeredSensorQueue, new TriggeredSensorComparator());

		return triggeredSensorQueue;
	}

	/**
	 * Determines the time between the {@link Event} at the head of the Queue and the
	 * {@link Event} at the tail of the Queue.
	 *
	 * @param queue a queue of {@link Event}s
	 * @param tailEvent the {@link Event} at the tail of the queue
	 * @return the duration of the queue as an {@link Interval}
	 */
	public Interval getQueueInterval(Queue<Event> queue, Event tailEvent) {
		DateTime endTime = DateUtils.fromString(tailEvent.getTimestamp());
		DateTime startTime = DateUtils.fromString(queue.peek().getTimestamp());

		return new Interval((int)endTime.minus(startTime.getMillis()).getMillis(), "milliseconds");
	}

	/**
	 * Determines whether a queue of {@link Event}s crosses a {@link Threshold} in the correct
	 * amount of time.
	 *
	 * @param queue a queue of {@link Event}s
	 * @param tailEvent the {@link Event} at the tail of the queue
	 * @param threshold the {@link Threshold} to evaluate
	 * @return boolean evaluation of the {@link Threshold}
	 */
	public boolean isThresholdViolated(Queue<Event> queue, Event tailEvent, Threshold threshold) {
		if (queue.size() >= threshold.getCount()) {

			Interval queueInterval = getQueueInterval(queue, tailEvent);

			if (queueInterval.toMillis() <= threshold.getInterval().toMillis()) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Generates an attack form the given {@link Rule} and triggered {@link Event}
	 *
	 * @param triggerEvent the {@link Event} that triggered the {@link Rule}
	 * @param rule the {@link Rule} being evaluated
	 */
	public void generateAttack(Event triggerEvent, Rule rule) {
		logger.debug("Attack generated on rule: " + rule.getName() + ", by event: " + triggerEvent.toString());

		Attack attack = new Attack();
		attack.setUser(new User(triggerEvent.getUser().getUsername()));
		attack.setRule(rule.getName());
		attack.setTimestamp(triggerEvent.getTimestamp());
		attack.setDetectionSystem(triggerEvent.getDetectionSystem());
		attack.setResource(triggerEvent.getResource());

		appSensorServer.getAttackStore().addAttack(attack);
	}

	/**
	 * Finds all {@link Rule}s that could have been triggered by the {@link Event}. A
	 * trigger {@link Event} must be the final {@link Event} so if the corresponding
	 * {@link RulesDetectionPoint} is in the {@link Rule}'s final {@link Expression} it should
	 * be evaluated.
	 *
	 * @param triggerEvent the {@link Event} that triggered the {@link Rule}
	 * @return a list of {@link Rule}s applicable to triggerEvent
	 */
	protected ArrayList<Rule> getApplicableRules(Event triggerEvent) {
		ArrayList<Rule> matches = new ArrayList<Rule>();

		for (Rule rule : rules) {
			if (rule.checkLastExpressionForDetectionPoint(triggerEvent.getDetectionPoint())) {
				matches.add(rule);
			}
		}

		return matches;
	}

	/**
	 * Finds all {@link Event}s that related to the {@link Rule} being evaluated.
	 *
	 * @param triggerEvent the {@link Event} that triggered the {@link Rule}
	 * @param rule the {@link Rule} being evaluated
	 * @return a list of {@link Event}s applicable to {@link Rule}
	 */
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

	// TODO: will be removed one hack gets fixed
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
	}

	public void removeRule(Rule rule) {
		if (rules != null) {
			rules.remove(rule);
		}
	}

	public void clearRules() {
		if (rules != null) {
			rules.clear();
		}
	}

	public ArrayList<Rule> getRules() {
		return this.rules;
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
