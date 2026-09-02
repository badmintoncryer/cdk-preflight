package cdk_preflight

import rego.v1

# An alarm on a Metrics array needs exactly one query returning data.
# ReturnData defaults to true when absent (bench w04b), and explicit false
# everywhere is rejected too (w04c). A query whose ReturnData is an
# unresolvable intrinsic makes the count unknowable, so the rule skips.
_pf_cwmqr_countable(q) if object.get(q, "ReturnData", "__pf_absent") == "__pf_absent"

_pf_cwmqr_countable(q) if is_boolean(object.get(q, "ReturnData", null))

_pf_cwmqr_returns(q) if object.get(q, "ReturnData", true) == true

violation contains make_diag_full("pf-cloudwatch-metric-query-returndata", "ERROR", name,
	"Properties.Metrics",
	sprintf("%d of the metric queries return data (ReturnData defaults to true); PutMetricAlarm fails with \"Exactly one element of the metrics list should return data.\"", [n]),
	"Set ReturnData: false on every query except the one the alarm should watch",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-cloudwatch-alarm-metricdataquery.html") if {
	some name in resources_of_type("AWS::CloudWatch::Alarm")
	items := [q | some q in flatten_list(name, "Properties.Metrics")]
	count(items) > 0
	every q in items {
		is_object(q.value)
		_pf_cwmqr_countable(q.value)
	}
	n := count([q | some q in items; _pf_cwmqr_returns(q.value)])
	n != 1
}
