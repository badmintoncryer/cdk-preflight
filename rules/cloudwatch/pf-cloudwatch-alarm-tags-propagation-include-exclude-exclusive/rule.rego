package cdk_preflight

import rego.v1

# Added to the schema in 2026-10. The engine (1.14.0) knows both keys but not
# that they exclude each other; PutMetricAlarm rejects the pair.
violation contains make_diag_full("pf-cloudwatch-alarm-tags-propagation-include-exclude-exclusive", "ERROR", name,
	"Properties.ActionConfiguration.AlarmTagsPropagation",
	"AlarmTagsPropagation sets both IncludedTagKeys and ExcludedTagKeys; PutMetricAlarm fails with \"IncludedTagKeys and ExcludedTagKeys cannot be specified in the same AlarmTagsPropagation\"",
	"Keep only one of IncludedTagKeys and ExcludedTagKeys",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-cloudwatch-alarm-alarmtagspropagation.html") if {
	some name in resources_of_type("AWS::CloudWatch::Alarm")
	p := resolve(name, "Properties.ActionConfiguration.AlarmTagsPropagation")
	is_object(p)
	object.get(p, "IncludedTagKeys", null) != null
	object.get(p, "ExcludedTagKeys", null) != null
}
