package cdk_preflight

import rego.v1

# The set is the documented action list: EC2 (automate), SNS, Auto Scaling,
# Systems Manager OpsItems and Incidents, and Lambda.
# ponytail: an allowlist, so a newly supported vendor would false-positive
# until this set is updated.
_pf_cwav_vendors := {"automate", "sns", "autoscaling", "ssm", "ssm-incidents", "lambda"}

violation contains make_diag_full("pf-cloudwatch-alarm-action-vendor", "ERROR", name,
	sprintf("Properties.%s", [key]),
	sprintf("Alarm action ARN names the service '%s'; PutMetricAlarm fails with \"Unsupported AWS vendor %s\"", [vendor, vendor]),
	"Point alarm actions at an SNS topic, an Auto Scaling policy, an EC2 automate action, an SSM OpsItem or response plan, or a Lambda function",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutMetricAlarm.html") if {
	some name in resources_of_type("AWS::CloudWatch::Alarm")
	some key in _pf_cwlib_action_keys
	some item in flatten_list(name, sprintf("Properties.%s", [key]))
	parts := _pf_cwlib_arn(item.value)
	vendor := parts[2]
	not vendor in _pf_cwav_vendors
}
