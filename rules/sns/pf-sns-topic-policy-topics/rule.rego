package cdk_preflight

import rego.v1

_pf_snstp_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-sns-topicpolicy.html"

_pf_snstp_fix := "List topics with Ref (the ARN), not Fn::GetAtt Topic.TopicName or a bare name"

violation contains make_diag_full("pf-sns-topic-policy-topics", "ERROR", name,
	sprintf("Properties.Topics.%d", [i]),
	"Topics entry is the topic name (Fn::GetAtt Topic.TopicName) but TopicPolicy expects the topic ARN; the resource handler fails with \"Invalid parameter: TopicArn Reason: An ARN must have at least 6 elements, not 1\"",
	_pf_snstp_fix, _pf_snstp_url) if {
	some name in resources_of_type("AWS::SNS::TopicPolicy")
	ts := object.get(input.resources[name].properties, "Topics", null)
	is_array(ts)
	some i, t in ts
	is_object(t)
	object.get(t, "__kind", null) == "getatt:TopicName"
}

violation contains make_diag_full("pf-sns-topic-policy-topics", "ERROR", name,
	sprintf("Properties.Topics.%d", [i]),
	sprintf("Topics entry '%s' is not an ARN; the resource handler fails with \"Invalid parameter: TopicArn Reason: An ARN must have at least 6 elements\"", [t]),
	_pf_snstp_fix, _pf_snstp_url) if {
	some name in resources_of_type("AWS::SNS::TopicPolicy")
	ts := object.get(input.resources[name].properties, "Topics", null)
	is_array(ts)
	some i, t in ts
	is_string(t)
	not startswith(t, "arn:")
	not contains(t, "${")
}
