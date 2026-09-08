package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-logs-account-policy-subscription-document", "ERROR", name,
	"Properties.PolicyDocument",
	"The subscription policy document has no DestinationArn; PutAccountPolicy fails with \"MissingDestinationArnfield in policy document\"",
	"Add DestinationArn (and FilterPattern) to the policy document",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutAccountPolicy.html") if {
	some name in resources_of_type("AWS::Logs::AccountPolicy")
	resolve(name, "Properties.PolicyType") == "SUBSCRIPTION_FILTER_POLICY"
	obj := _pf_lglib_json(resolve(name, "Properties.PolicyDocument"))
	object.get(obj, "DestinationArn", "__pf_absent") == "__pf_absent"
}
