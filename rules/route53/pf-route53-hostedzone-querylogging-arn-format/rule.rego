package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-hostedzone-querylogging-arn-format", "ERROR", name,
	"Properties.QueryLoggingConfig.CloudWatchLogsLogGroupArn",
	sprintf("%s is not a CloudWatch Logs log group ARN (arn:<partition>:logs:<region>:<account>:log-group:<name>)", [a]),
	"Use Fn::GetAtt on the log group's Arn, or spell the full log-group ARN",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/query-logs.html") if {
	some name in resources_of_type("AWS::Route53::HostedZone")
	a := _pf_r53z_qlog_arn(name)
	not regex.match(`^arn:[a-z0-9-]+:logs:[a-z0-9-]+:[0-9]{12}:log-group:`, a)
}
