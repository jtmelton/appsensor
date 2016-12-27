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
import org.owasp.appsensor.core.rule.Clause;
import org.owasp.appsensor.core.rule.Expression;
import org.owasp.appsensor.core.rule.Rule;
import org.owasp.appsensor.core.rule.RulesDetectionPoint;
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

	//private ArrayList<Rule> rules;

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
		Collection<Rule> rules = appSensorServer.getConfiguration().findRules(triggerEvent);

		for (Rule rule : rules) {
			if (checkRule(triggerEvent, rule)) {
				generateAttack(triggerEvent, rule);
			}
		}
	}

	/**
	 * Evaluates a {@link Rule}'s boolean logic by compiling a list of all {@link Notification}
	 * and then evaluating each {@link Expression} within the {@link Rule}. All {@link Expression}s
	 * evaluate to true within the {@link Rule}'s window for the {@link Rule} to evaluate to true.
	 * The process follows the "sliding window" pattern.
	 *
	 * @param event the {@link Event} that triggered analysis
	 * @param rule the {@link Rule} being evaluated
	 * @return the boolean evaluation of the {@link Rule}
	 */
	protected boolean checkRule(Event triggerEvent, Rule rule) {
		Queue<Notification> notifications = getNotifications(triggerEvent, rule);
		Queue<Notification> windowSensors = new LinkedList<Notification>();
		Iterator<Expression> expressions = rule.getExpressions().iterator();
		Expression currentExpression = expressions.next();

		while (!notifications.isEmpty()) {
			Notification tail = notifications.poll();
			windowSensors.add(tail);
			trim(windowSensors, tail.getEndTime().minus(currentExpression.getWindow().toMillis()));

			if (checkExpression(currentExpression, windowSensors)) {
				if (expressions.hasNext()) {
					currentExpression = expressions.next();
					windowSensors = new LinkedList<Notification>();
					trim(notifications, tail.getEndTime());
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
	 * @param windowSensors the {@link Notification}s in the current "sliding window"
	 * @return the boolean evaluation of the {@link Expression}
	 */
	protected boolean checkExpression(Expression expression, Queue<Notification> windowSensors) {
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
	 * @param windowSensors the {@link Notification}s in the current "sliding window"
	 * @return the boolean evaluation of the {@link Clause}
	 */
	protected boolean checkClause(Clause clause, Queue<Notification> windowSensors) {
		Collection<DetectionPoint> windowDetectionPoints = new ArrayList<DetectionPoint>();

		for (Notification notification : windowSensors) {
			windowDetectionPoints.add(notification.getDetectionPoint());
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
	 * Pops {@link Notification}s out of the queue until the start time of the queue's head
	 * is after the parameter time.
	 *
	 * @param notifications the queue of {@link Notification}s being trimmed
	 * @param time the time that all {@link Notification}s in the queue must be after
	 */
	protected void trim(Queue<Notification> notifications, DateTime time) {
		while (!notifications.isEmpty() && !notifications.peek().getStartTime().isAfter(time)) {
			notifications.poll();
		}
	}

	/**
	 * Builds a queue of all {@link Notifications} from the events relating to the
	 * current {@link Rule}. The {@link Notifications} are ordered in the Queue by
	 * start time.
	 *
	 * @param triggerEvent the {@link Event} that triggered analysis
	 * @param rule the {@link Rule} being evaluated
	 * @return a queue of {@link TriggerEvents}
	 */
	protected LinkedList<Notification> getNotifications(Event triggerEvent, Rule rule) {
		LinkedList<Notification> notificationQueue = new LinkedList<Notification>();
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

						Notification notification = new Notification(queueDuration, "milliseconds", start, detectionPoint);
						notificationQueue.add(notification);
					}

					if (eventQueue.size() >= detectionPoint.getThreshold().getCount()) {
						eventQueue.poll();
					}
				}
			}
		}

		Collections.sort(notificationQueue, Notification.getStartTimeAscendingComparator());

		return notificationQueue;
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
	 * Determines the time between the {@link Event} at the head of the queue and the
	 * {@link Event} at the tail of the queue.
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
	 * Generates an attack form the given {@link Rule} and triggered {@link Event}
	 *
	 * @param triggerEvent the {@link Event} that triggered the {@link Rule}
	 * @param rule the {@link Rule} being evaluated
	 */
	public void generateAttack(Event triggerEvent, Rule rule) {
		logger.debug("Attack generated on rule: " + rule.getName() + ", by event: " + triggerEvent.toString());

		Attack attack = new Attack();
		attack.setUser(new User(triggerEvent.getUser().getUsername()));
		attack.setRule(rule);
		attack.setTimestamp(triggerEvent.getTimestamp());
		attack.setDetectionSystem(triggerEvent.getDetectionSystem());
		attack.setResource(triggerEvent.getResource());

		appSensorServer.getAttackStore().addAttack(attack);
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
				setEarliest(findMostRecentAttackTime(triggerEvent, rule).plus(1).toString()).
				setRule(rule).
				setDetectionSystemIds(appSensorServer.getConfiguration().getRelatedDetectionSystems(triggerEvent.getDetectionSystem()));

		events = (ArrayList<Event>)appSensorServer.getEventStore().findEvents(criteria);

		Collections.sort(events, Event.getTimeAscendingComparator());

		return events;
	}

	/**
	 * Finds the most recent {@link Attack} from the {@link Rule} being evaluated.
	 *
	 * @param triggerEvent the {@link Event} that triggered the {@link Rule}
	 * @param rule the {@link Rule} being evaluated
	 * @return a {@link DateTime} of the most recent attack related to the {@link Rule}
	 */
	protected DateTime findMostRecentAttackTime(Event triggerEvent, Rule rule) {
		DateTime newest = DateUtils.epoch();

		SearchCriteria criteria = new SearchCriteria().
				setUser(new User(triggerEvent.getUser().getUsername())).
				setRule(rule).
				setDetectionSystemIds(appSensorServer.getConfiguration().getRelatedDetectionSystems(triggerEvent.getDetectionSystem()));

		Collection<Attack> attacks = appSensorServer.getAttackStore().findAttacks(criteria);

		for (Attack attack : attacks) {
			if (attack.getRule().equals(rule)) {
				if (DateUtils.fromString(attack.getTimestamp()).isAfter(newest)) {
					newest = DateUtils.fromString(attack.getTimestamp());
				}
			}
		}

		return newest;
	}
}
