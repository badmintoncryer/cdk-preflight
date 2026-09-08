package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cloudwatch-alarm-actions-max", "ERROR", name,
	sprintf("Properties.%s", [key]),
	sprintf("%s has %d entries; PutMetricAlarm accepts at most 5 and fails with \"failed to satisfy constraint: Member must have length less than or equal to 5\"", [key, n]),
	"Fan out through a single SNS topic instead of listing more than 5 actions",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutMetricAlarm.html") if {
	some name in resources_of_type("AWS::CloudWatch::Alarm")
	some key in _pf_cwlib_action_keys
	items := [x | some x in flatten_list(name, sprintf("Properties.%s", [key]))]
	n := count(items)
	n > 5
}
