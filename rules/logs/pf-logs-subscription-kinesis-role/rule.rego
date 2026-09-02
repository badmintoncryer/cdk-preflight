package cdk_preflight

import rego.v1

_pf_lgskr_url := "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/SubscriptionFilters.html"

# The destination is provably Kinesis two ways: a literal
# arn:<partition>:kinesis: string, or a Ref/GetAtt that resolve() turns into
# the logical ID of an in-template AWS::Kinesis::Stream. Scoped to Kinesis —
# the bench error names "vendor kinesis"; other vendors were not measured.
_pf_lgskr_kinesis_dest(name) if {
	d := resolve(name, "Properties.DestinationArn")
	is_string(d)
	parts := split(d, ":")
	count(parts) >= 3
	parts[0] == "arn"
	parts[2] == "kinesis"
}

_pf_lgskr_kinesis_dest(name) if {
	d := resolve(name, "Properties.DestinationArn")
	is_string(d)
	d in resources_of_type("AWS::Kinesis::Stream")
}

# True absence of RoleArn needs the preprocessed document (see AGENTS.md).
_pf_lgskr_role_absent(name) if {
	props := input.resources[name].properties
	is_object(props)
	object.get(props, "RoleArn", "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-logs-subscription-kinesis-role", "ERROR", name,
	"Properties.RoleArn",
	"The subscription filter targets a Kinesis stream but sets no RoleArn; the service rejects it with \"destinationArn for vendor kinesis cannot be used without roleArn\"",
	"Add a RoleArn for a role that logs.amazonaws.com can assume with kinesis:PutRecord on the stream",
	_pf_lgskr_url) if {
	some name in resources_of_type("AWS::Logs::SubscriptionFilter")
	_pf_lgskr_kinesis_dest(name)
	_pf_lgskr_role_absent(name)
}
