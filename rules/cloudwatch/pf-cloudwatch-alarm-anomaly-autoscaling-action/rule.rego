package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cloudwatch-alarm-anomaly-autoscaling-action", "ERROR", name,
	sprintf("Properties.%s", [key]),
	"The alarm sets ThresholdMetricId (anomaly detection) and an Auto Scaling action; PutMetricAlarm fails with \"autoscaling actions not supported when ThresholdMetricId is set\"",
	"Drive scaling from a separate static-threshold alarm, or drop the Auto Scaling action from the anomaly alarm",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutMetricAlarm.html") if {
	some name in resources_of_type("AWS::CloudWatch::Alarm")
	is_string(resolve(name, "Properties.ThresholdMetricId"))
	some key in _pf_cwlib_action_keys
	some item in flatten_list(name, sprintf("Properties.%s", [key]))
	parts := _pf_cwlib_arn(item.value)
	parts[2] == "autoscaling"
}
