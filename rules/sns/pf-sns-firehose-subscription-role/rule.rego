package cdk_preflight

import rego.v1

_pf_snsfh_url := "https://docs.aws.amazon.com/sns/latest/api/API_Subscribe.html"

_pf_snsfh_fix := "Set SubscriptionRoleArn to a role SNS can assume that may write to the delivery stream"

_pf_snsfh_sub contains [name, "Properties", sub, topic] if {
	some name in resources_of_type("AWS::SNS::Subscription")
	sub := input.resources[name].properties
	is_object(sub)
	topic := resolve(name, "Properties.TopicArn")
	is_string(topic)
}

_pf_snsfh_sub contains [name, path, sub, name] if {
	some name in resources_of_type("AWS::SNS::Topic")
	some s in flatten_list(name, "Properties.Subscription")
	sub := s.value
	is_object(sub)
	path := sprintf("Properties.Subscription.%d", [s.index])
}

_pf_snsfh_proto(name, path) := p if {
	p := resolve(name, sprintf("%s.Protocol", [path]))
	is_string(p)
}

violation contains make_diag_full("pf-sns-firehose-subscription-role", "ERROR", name,
	sprintf("%s.SubscriptionRoleArn", [path]),
	"Protocol firehose has no SubscriptionRoleArn; Subscribe fails with \"Invalid parameter: Delivery protocol firehose can only be subscribed with subscription role arn\"",
	_pf_snsfh_fix, _pf_snsfh_url) if {
	some [name, path, sub, _] in _pf_snsfh_sub
	_pf_snsfh_proto(name, path) == "firehose"
	object.get(sub, "SubscriptionRoleArn", "__pf_absent") == "__pf_absent"
}
