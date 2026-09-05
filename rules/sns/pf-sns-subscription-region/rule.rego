package cdk_preflight

import rego.v1

_pf_snssrg_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-sns-subscription.html"

_pf_snssrg_fix := "Set Region to the topic's own region, or drop it for a topic in this stack"

violation contains make_diag_full("pf-sns-subscription-region", "ERROR", name,
	"Properties.Region",
	sprintf("Region '%s' differs from the topic's region '%s' in TopicArn; the resource handler fails with \"Invalid parameter: TopicArn\"", [reg, parts[3]]),
	_pf_snssrg_fix, _pf_snssrg_url) if {
	some name in resources_of_type("AWS::SNS::Subscription")
	reg := resolve(name, "Properties.Region")
	is_string(reg)
	t := resolve(name, "Properties.TopicArn")
	is_string(t)
	startswith(t, "arn:")
	parts := split(t, ":")
	count(parts) >= 6
	parts[3] != reg
}

# A topic created in this template lives in the deploy region (enforce mode only; see AGENTS.md).
violation contains make_diag_full("pf-sns-subscription-region", "ERROR", name,
	"Properties.Region",
	sprintf("Region '%s' differs from the deploy region '%s' of the topic in this template; the resource handler fails with \"Invalid parameter: TopicArn\"", [reg, region]),
	_pf_snssrg_fix, _pf_snssrg_url) if {
	region := data.cdk_preflight.deploy_region
	some name in resources_of_type("AWS::SNS::Subscription")
	reg := resolve(name, "Properties.Region")
	is_string(reg)
	t := resolve(name, "Properties.TopicArn")
	t in resources_of_type("AWS::SNS::Topic")
	reg != region
}
