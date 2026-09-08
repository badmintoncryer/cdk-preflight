package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-logs-account-policy-document-json", "ERROR", name,
	"Properties.PolicyDocument",
	"PolicyDocument is not valid JSON; PutAccountPolicy fails with \"Malformed Subscription filter policy\"",
	"Render the document with JSON.stringify / Fn::ToJsonString instead of hand-written JSON",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutAccountPolicy.html") if {
	some name in resources_of_type("AWS::Logs::AccountPolicy")
	doc := resolve(name, "Properties.PolicyDocument")
	is_string(doc)
	not json.is_valid(doc)
}
