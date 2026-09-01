package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-iam-managed-policy-size", "ERROR", name,
	"Properties.PolicyDocument",
	sprintf("PolicyDocument is %d characters (JSON without whitespace) but the managed policy limit is 6144", [size]),
	"Split the document into multiple managed policies or shorten it",
	"https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html") if {
	some name in resources_of_type("AWS::IAM::ManagedPolicy")
	doc := resolve(name, "Properties.PolicyDocument")
	is_object(doc)
	size := count(json.marshal(doc))
	size > 6144
}
