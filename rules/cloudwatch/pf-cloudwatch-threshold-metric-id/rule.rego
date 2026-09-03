package cdk_preflight

import rego.v1

# Matching means Id equality AND effective ReturnData true (default true,
# bench w04b); w12 proved an Id match with ReturnData false does not count.
# Only n == 0 fires - the duplicate-match side is unbenched. Queries with
# unresolvable Id/ReturnData make the count unknowable, so the rule skips.
_pf_cwtmi_countable(q) if object.get(q, "ReturnData", "__pf_absent") == "__pf_absent"

_pf_cwtmi_countable(q) if is_boolean(object.get(q, "ReturnData", null))

_pf_cwtmi_matches(q, tmid) if {
	object.get(q, "Id", null) == tmid
	object.get(q, "ReturnData", true) == true
}

violation contains make_diag_full("pf-cloudwatch-threshold-metric-id", "ERROR", name,
	"Properties.ThresholdMetricId",
	sprintf("No metric query with Id '%s' returns data; PutMetricAlarm fails with \"Metrics list must contain exactly one metric matching the ThresholdMetricId parameter\"", [tmid]),
	"Point ThresholdMetricId at a query whose ReturnData is true",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cloudwatch-alarm.html") if {
	some name in resources_of_type("AWS::CloudWatch::Alarm")
	tmid := resolve(name, "Properties.ThresholdMetricId")
	is_string(tmid)
	items := [q | some q in flatten_list(name, "Properties.Metrics")]
	count(items) > 0
	every q in items {
		is_object(q.value)
		is_string(object.get(q.value, "Id", null))
		_pf_cwtmi_countable(q.value)
	}
	count([q | some q in items; _pf_cwtmi_matches(q.value, tmid)]) == 0
}
