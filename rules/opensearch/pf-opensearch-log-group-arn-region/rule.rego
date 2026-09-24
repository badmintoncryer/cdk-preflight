package cdk_preflight

import rego.v1

# data.cdk_preflight.deploy_region is injected only in enforce mode; the rule
# stays silent otherwise.

violation contains make_diag_full("pf-opensearch-log-group-arn-region", "ERROR", name,
	"Properties.LogPublishingOptions",
	sprintf("the %v log group is in %v but the domain deploys to %v; CreateDomain answers \"The CloudWatch Logs ARN referring to the log group for logging your %v logs is invalid.\"", [k, r, reg, k]),
	"Reference a log group in the Region the domain deploys into",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-opensearchservice-domain-logpublishingoption.html") if {
	some name in _pf_os_domains
	reg := data.cdk_preflight.deploy_region
	is_string(reg)
	opts := _pf_os_at(name, "LogPublishingOptions")
	is_object(opts)
	some k, _v in opts
	r := _pf_os_arn_region(resolve(name, sprintf("Properties.LogPublishingOptions.%v.CloudWatchLogsLogGroupArn", [k])))
	r != reg
}
