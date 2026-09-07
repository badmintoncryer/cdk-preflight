package cdk_preflight

import rego.v1

# "ScheduleExpression is supported only on the default event bus." Measured
# 2026-09-07, events:PutRule, us-east-1, against a real custom bus; the same
# expression on the default bus deploys.
violation contains make_diag_full("pf-events-rule-schedule-default-bus", "ERROR", name,
	"Properties.ScheduleExpression",
	sprintf("A scheduled rule must live on the default bus, but EventBusName is '%s'; PutRule fails with \"ScheduleExpression is supported only on the default event bus\"", [bus]),
	"Drop EventBusName, or use EventBridge Scheduler for a schedule on a custom bus",
	"https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-create-rule-schedule.html") if {
	some name in resources_of_type("AWS::Events::Rule")
	is_string(resolve(name, "Properties.ScheduleExpression"))
	bus := resolve(name, "Properties.EventBusName")
	is_string(bus)
	bus != "default"
}
