package cdk_preflight

import rego.v1

# Same two types as the groups rule, for the same reason.
violation contains make_diag_full("pf-eks-accessentry-node-type-forbids-policies", "ERROR", name,
	"Properties.AccessPolicies",
	sprintf("a %v access entry cannot have access policies associated (\"This operation can only be performed on Access Entries with a type of \\\"STANDARD\\\"\")", [t]),
	"Drop AccessPolicies, or use type STANDARD",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-eks-accessentry.html") if {
	some name in resources_of_type("AWS::EKS::AccessEntry")
	t := resolve(name, "Properties.Type")
	t in {"EC2_LINUX", "EC2_WINDOWS"}
	count(flatten_list(name, "Properties.AccessPolicies")) > 0
}
