package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-logs-resource-policy-json", "ERROR", name,
	"Properties.PolicyDocument",
	"PolicyDocument is not an IAM policy document; PutResourcePolicy fails with \"Error occurred while parsing accessPolicy. Please check if the accessPolicy has been constructed correctly using IAM grammar.\"",
	"Render the policy with iam.PolicyDocument (a Version plus a Statement array)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-logs-resourcepolicy.html") if {
	some name in resources_of_type("AWS::Logs::ResourcePolicy")
	p := resolve(name, "Properties.PolicyDocument")
	is_string(p)
	not _pf_lgdpj_iam(p)
}
