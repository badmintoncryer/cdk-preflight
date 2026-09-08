package cdk_preflight

import rego.v1

# ponytail: literal string matching only. An AlarmRule built with Fn::Sub over
# a Ref is undefined under resolve() and is skipped.
_pf_cwsref_hit(r, n) if contains(r, sprintf("\"%s\"", [n]))

_pf_cwsref_hit(r, n) if contains(r, sprintf("ALARM(%s)", [n]))

_pf_cwsref_hit(r, n) if contains(r, sprintf(":alarm:%s", [n]))

violation contains make_diag_full("pf-cloudwatch-composite-self-reference", "ERROR", name,
	"Properties.AlarmRule",
	sprintf("The AlarmRule references the composite alarm's own name '%s'; PutCompositeAlarm fails with \"A composite alarm cannot have a child relation with itself via its AlarmRule\"", [n]),
	"Reference the child alarms, not the composite alarm itself",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutCompositeAlarm.html") if {
	some name in resources_of_type("AWS::CloudWatch::CompositeAlarm")
	n := resolve(name, "Properties.AlarmName")
	is_string(n)
	r := resolve(name, "Properties.AlarmRule")
	is_string(r)
	_pf_cwsref_hit(r, n)
}
