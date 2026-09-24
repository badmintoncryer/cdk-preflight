package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-opensearch-log-publishing-requires-arn", "ERROR", name,
	"Properties.LogPublishingOptions",
	sprintf("%v is enabled without a CloudWatchLogsLogGroupArn; CreateDomain answers \"Log publishing option is misconfigured. Enter valid CloudWatch Logs Arn and Enable flag for LogType\"", [k]),
	"Set CloudWatchLogsLogGroupArn on the entry, or leave the log type out",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-opensearchservice-domain-logpublishingoption.html") if {
	some name in _pf_os_domains
	opts := _pf_os_at(name, "LogPublishingOptions")
	is_object(opts)
	some k, v in opts
	is_object(v)
	v.Enabled == true
	object.get(v, "CloudWatchLogsLogGroupArn", "__pf_absent") == "__pf_absent"
}
