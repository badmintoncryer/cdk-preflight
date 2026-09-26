package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-aps-ws-log-group-arn-format", "ERROR", name,
	"Properties.LoggingConfiguration.LogGroupArn",
	sprintf("LogGroupArn %v is not a CloudWatch Logs log-group ARN ending in \":*\"; CreateWorkspace fails with \"Invalid logGroupArn: Member must satisfy regular expression pattern: arn:aws[a-z0-9-]*:logs:[a-z0-9-]+:[0-9]{12}:log-group:[A-Za-z0-9\\.\\-\\_\\#/]{1,512}\\:\\*\"", [arn]),
	"Pass the log group's Arn attribute (it already ends in :*), not a name-built ARN",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-aps-workspace-loggingconfiguration.html") if {
	some name in resources_of_type("AWS::APS::Workspace")
	arn := _pf_aps_str(name, "Properties.LoggingConfiguration.LogGroupArn")
	not regex.match(`^arn:aws[a-z0-9-]*:logs:[a-z0-9-]+:[0-9]{12}:log-group:[A-Za-z0-9._#/-]+:\*$`, arn)
}
