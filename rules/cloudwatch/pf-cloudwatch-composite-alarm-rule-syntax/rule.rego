package cdk_preflight

import rego.v1

# The service names the only tokens a rule expression may start with; this
# checks just that first token — a full grammar is out of scope. Function
# tokens take an argument list, keywords stand alone.
_pf_cwcas_valid_start(t) if startswith(t, "(")

_pf_cwcas_valid_start(t) if startswith(t, "NOT ")

_pf_cwcas_valid_start(t) if startswith(t, "NOT(")

_pf_cwcas_valid_start(t) if startswith(t, "AT_LEAST")

_pf_cwcas_valid_start(t) if t == "TRUE"

_pf_cwcas_valid_start(t) if t == "FALSE"

_pf_cwcas_valid_start(t) if startswith(t, "ALARM(")

_pf_cwcas_valid_start(t) if startswith(t, "OK(")

_pf_cwcas_valid_start(t) if startswith(t, "INSUFFICIENT_DATA(")

violation contains make_diag_full("pf-cloudwatch-composite-alarm-rule-syntax", "ERROR", name,
	"Properties.AlarmRule",
	sprintf("AlarmRule '%s' does not start with a valid token; the service rejects it with \"Error in AlarmRule [Unsupported token ... must be: '(', 'NOT', AT_LEAST, TRUE or FALSE, ALARM, OK, or INSUFFICIENT_DATA]\"", [expr]),
	"Start the rule with ALARM(...), OK(...), INSUFFICIENT_DATA(...), NOT, AT_LEAST, TRUE, FALSE, or a parenthesized group",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Create_Composite_Alarm.html") if {
	some name in resources_of_type("AWS::CloudWatch::CompositeAlarm")
	expr := resolve(name, "Properties.AlarmRule")
	is_string(expr)
	t := trim_space(expr)
	t != ""
	not _pf_cwcas_valid_start(t)
}
