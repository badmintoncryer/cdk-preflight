package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cloudtrail-trail-cwl-loggroup-region", "ERROR", name,
	"Properties.CloudWatchLogsLogGroupArn",
	sprintf("the log group is in %v but the trail deploys to %v; CreateTrail fails with \"You must specify a log group that is in the current region\"", [r, data.cdk_preflight.deploy_region]),
	"Reference a log group in the deployment Region",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cloudtrail-trail.html") if {
	some name in resources_of_type("AWS::CloudTrail::Trail")
	v := resolve(name, "Properties.CloudWatchLogsLogGroupArn")
	_pf_ctlib_arn_of(v, "logs")
	r := _pf_ctlib_region_mismatch(v)
}
