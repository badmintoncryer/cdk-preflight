package cdk_preflight

import rego.v1

# The selector namespace is matched against Kubernetes namespaces and accepts
# the wildcards * and ?; count(ns) <= 63 only keeps the format check away from
# strings that are already too long to be a label.
violation contains make_diag_full("pf-eks-fargate-selector-namespace-format", "ERROR", name,
	sprintf("Properties.Selectors.%v.Namespace", [s.index]),
	sprintf("selector namespace %v is not a DNS-1123 label (\"The namespace provided is invalid.\")", [ns]),
	"Use lowercase letters, digits and hyphens (plus * and ? wildcards), starting and ending with an alphanumeric",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-eks-fargateprofile-selector.html") if {
	some name in resources_of_type("AWS::EKS::FargateProfile")
	some s in flatten_list(name, "Properties.Selectors")
	ns := _pf_ekslib_oget(s.value, "Namespace")
	_pf_ekslib_lit(ns)
	count(ns) <= 63
	not regex.match(`^[a-z0-9*?]([-a-z0-9*?]*[a-z0-9*?])?$`, ns)
}
