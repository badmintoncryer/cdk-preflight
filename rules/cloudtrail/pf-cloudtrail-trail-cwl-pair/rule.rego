package cdk_preflight

import rego.v1

_pf_ctcwl_other := {"CloudWatchLogsLogGroupArn": "CloudWatchLogsRoleArn", "CloudWatchLogsRoleArn": "CloudWatchLogsLogGroupArn"}

violation contains make_diag_full("pf-cloudtrail-trail-cwl-pair", "ERROR", name,
	sprintf("Properties.%v", [have]),
	sprintf("the trail sets %v without %v; CloudTrail requires both to deliver events to CloudWatch Logs", [have, want]),
	"Set CloudWatchLogsLogGroupArn and CloudWatchLogsRoleArn together, or drop both",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cloudtrail-trail.html") if {
	some name in resources_of_type("AWS::CloudTrail::Trail")
	some have, want in _pf_ctcwl_other
	_pf_ctlib_has(name, have)
	not _pf_ctlib_has(name, want)
}
