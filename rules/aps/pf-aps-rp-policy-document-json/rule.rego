package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-aps-rp-policy-document-json", "ERROR", name,
	"Properties.PolicyDocument",
	"PolicyDocument is not parseable JSON; PutResourcePolicy fails with \"Workspace resource policy cannot be malformed\"",
	"Render the document with JSON.stringify or Fn::ToJsonString so it always parses",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-aps-resourcepolicy.html") if {
	some name in resources_of_type("AWS::APS::ResourcePolicy")
	doc := _pf_aps_str(name, "Properties.PolicyDocument")
	not json.is_valid(doc)
}
