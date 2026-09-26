package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-aps-ws-log-group-arn-region", "ERROR", name,
	"Properties.LoggingConfiguration.LogGroupArn",
	sprintf("the log group is in %v but the workspace deploys into %v; CreateWorkspace fails with \"Invalid log group ARN - region: %v (expected: %v)\"", [m[1], region, m[1], region]),
	"Create the log group in the workspace's region",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-aps-workspace-loggingconfiguration.html") if {
	some name in resources_of_type("AWS::APS::Workspace")
	region := data.cdk_preflight.deploy_region
	is_string(region)
	arn := _pf_aps_str(name, "Properties.LoggingConfiguration.LogGroupArn")
	m := regex.find_all_string_submatch_n(`^arn:aws[a-z0-9-]*:logs:([a-z0-9-]+):`, arn, 1)[0]
	m[1] != region
}
