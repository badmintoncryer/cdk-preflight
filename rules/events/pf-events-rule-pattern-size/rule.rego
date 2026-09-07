package cdk_preflight

import rego.v1

# "Parameter EventPattern for rule <name> exceeds limit of 2048." Measured
# 2026-09-07, events:PutRule, us-east-1: 2015 bytes deploy and 2107 do not.
# The CloudFormation schema says Maximum 4096 and the quota page says 2,048 —
# the quota page is right, and above 4096 the request model rejects it first.
violation contains make_diag_full("pf-events-rule-pattern-size", "ERROR", name,
	"Properties.EventPattern",
	sprintf("The event pattern serialises to %d bytes; PutRule fails with \"Parameter EventPattern for rule ... exceeds limit of 2048\" (the CloudFormation schema's 4096 is wrong)", [n]),
	"Shorten the pattern, or split the rule",
	"https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-quota.html") if {
	some name in resources_of_type("AWS::Events::Rule")
	ep := _pf_evlib_pattern(name, "Properties.EventPattern")
	n := count(json.marshal(ep))
	n > 2048
}
