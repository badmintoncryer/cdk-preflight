package cdk_preflight

import rego.v1

_pf_cwsf_alarm_arn(parts) if {
	count(parts) >= 7
	parts[2] == "cloudwatch"
	parts[5] == "alarm"
}

violation contains make_diag_full("pf-cloudwatch-composite-suppressor-format", "ERROR", name,
	"Properties.ActionsSuppressor",
	sprintf("ActionsSuppressor '%s' is an ARN but not a CloudWatch alarm ARN; PutCompositeAlarm fails with \"ActionsSuppressor must be a valid CloudWatch Alarm ARN or an Alarm name\"", [s]),
	"Use the alarm name, or arn:<partition>:cloudwatch:<region>:<account>:alarm:<name>",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutCompositeAlarm.html") if {
	some name in resources_of_type("AWS::CloudWatch::CompositeAlarm")
	s := resolve(name, "Properties.ActionsSuppressor")
	parts := _pf_cwlib_arn(s)
	not _pf_cwsf_alarm_arn(parts)
}
