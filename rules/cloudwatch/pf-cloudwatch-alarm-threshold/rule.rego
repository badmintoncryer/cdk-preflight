package cdk_preflight

import rego.v1

_pf_cwath_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cloudwatch-alarm.html"

# The two range operators anchor to an anomaly-detection band via
# ThresholdMetricId; every other operator needs a static Threshold. Absence
# is proven against the preprocessed document (see AGENTS.md).
_pf_cwath_range_ops := {"LessThanLowerOrGreaterThanUpperThreshold", "LessThanLowerThreshold", "GreaterThanUpperThreshold"}

_pf_cwath_absent(name, key) if {
	props := input.resources[name].properties
	is_object(props)
	object.get(props, key, "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-cloudwatch-alarm-threshold", "ERROR", name,
	"Properties.Threshold",
	sprintf("ComparisonOperator '%s' needs a static Threshold but none is set; PutMetricAlarm fails with \"PutMetricAlarm request should have valid Threshold parameter\"", [op]),
	"Set Threshold, or switch to an anomaly-detection operator with ThresholdMetricId",
	_pf_cwath_url) if {
	some name in resources_of_type("AWS::CloudWatch::Alarm")
	op := resolve(name, "Properties.ComparisonOperator")
	is_string(op)
	not op in _pf_cwath_range_ops
	_pf_cwath_absent(name, "Threshold")
}

violation contains make_diag_full("pf-cloudwatch-alarm-threshold", "ERROR", name,
	"Properties.ThresholdMetricId",
	sprintf("ComparisonOperator '%s' is a range operator but ThresholdMetricId is not set; PutMetricAlarm fails with \"ComparisonOperators for ranges require ThresholdMetricId to be set\"", [op]),
	"Point ThresholdMetricId at the ANOMALY_DETECTION_BAND query id, or use a static-threshold operator",
	_pf_cwath_url) if {
	some name in resources_of_type("AWS::CloudWatch::Alarm")
	op := resolve(name, "Properties.ComparisonOperator")
	op in _pf_cwath_range_ops
	_pf_cwath_absent(name, "ThresholdMetricId")
}
