package cdk_preflight

import rego.v1

# Only the two types the CloudFormation page names are judged, as with the
# groups and policies rules.
violation contains make_diag_full("pf-eks-accessentry-username-only-standard", "ERROR", name,
	"Properties.Username",
	sprintf("a %v access entry cannot carry a Username (\"The specified username is invalid: setting username is not allowed when the type is \\\"%v\\\"\")", [t, t]),
	"Drop Username - EKS derives the node username itself - or use type STANDARD",
	"https://docs.aws.amazon.com/eks/latest/userguide/creating-access-entries.html") if {
	some name in resources_of_type("AWS::EKS::AccessEntry")
	t := resolve(name, "Properties.Type")
	t in {"EC2_LINUX", "EC2_WINDOWS"}
	_pf_ekslib_has(name, "Username")
}
