package cdk_preflight

import rego.v1

# An alarm on a Metrics array needs a fixed number of queries returning data,
# and the number depends on the alarm kind: one for a static-threshold alarm,
# two for an anomaly-detection alarm (the metric and the band both return,
# bench 2026-09-08). ReturnData defaults to true when absent (bench w04b), and
# explicit false everywhere is rejected too (w04c). A query whose ReturnData is
# an unresolvable intrinsic makes the count unknowable, so the rule skips.
_pf_cwmqr_countable(q) if object.get(q, "ReturnData", "__pf_absent") == "__pf_absent"

_pf_cwmqr_countable(q) if is_boolean(object.get(q, "ReturnData", null))

_pf_cwmqr_returns(q) if object.get(q, "ReturnData", true) == true

_pf_cwmqr_anomaly(name) if is_string(resolve(name, "Properties.ThresholdMetricId"))

_pf_cwmqr_expected(name) := 2 if _pf_cwmqr_anomaly(name)

_pf_cwmqr_expected(name) := 1 if not _pf_cwmqr_anomaly(name)

_pf_cwmqr_wording := {
	1: "Exactly one element of the metrics list should return data.",
	2: "Exactly two elements of the metrics list should return data.",
}

violation contains make_diag_full("pf-cloudwatch-metric-query-returndata", "ERROR", name,
	"Properties.Metrics",
	sprintf("%d of the metric queries return data (ReturnData defaults to true); PutMetricAlarm fails with \"%s\"", [n, _pf_cwmqr_wording[expected]]),
	"Set ReturnData so exactly one query returns data (two for an anomaly alarm: the metric and its ANOMALY_DETECTION_BAND)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-cloudwatch-alarm-metricdataquery.html") if {
	some name in resources_of_type("AWS::CloudWatch::Alarm")
	items := [q | some q in flatten_list(name, "Properties.Metrics")]
	count(items) > 0
	every q in items {
		is_object(q.value)
		_pf_cwmqr_countable(q.value)
	}
	expected := _pf_cwmqr_expected(name)
	n := count([q | some q in items; _pf_cwmqr_returns(q.value)])
	n != expected
}
