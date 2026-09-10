package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-hostedzone-querylogging-loggroup-region", "ERROR", name,
	"Properties.QueryLoggingConfig.CloudWatchLogsLogGroupArn",
	sprintf("the query logging log group is in %s; Route 53 only writes query logs to a log group in us-east-1", [rg]),
	"Create the log group in us-east-1 and point the hosted zone at it",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/query-logs.html") if {
	some name in resources_of_type("AWS::Route53::HostedZone")
	a := _pf_r53z_qlog_arn(name)
	startswith(a, "arn:")
	parts := split(a, ":")
	count(parts) > 4
	rg := parts[3]
	rg != ""
	rg != "us-east-1"
}
