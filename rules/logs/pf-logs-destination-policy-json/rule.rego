package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-logs-destination-policy-json", "ERROR", name,
	"Properties.DestinationPolicy",
	"DestinationPolicy is not an IAM policy document; PutDestinationPolicy fails with \"Error occurred while parsing accessPolicy. Please check if the accessPolicy has been constructed correctly using IAM grammar.\"",
	"Render the policy with iam.PolicyDocument (a Version plus a Statement array)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-logs-destination.html") if {
	some name in resources_of_type("AWS::Logs::Destination")
	p := resolve(name, "Properties.DestinationPolicy")
	is_string(p)
	not _pf_lgdpj_iam(p)
}
