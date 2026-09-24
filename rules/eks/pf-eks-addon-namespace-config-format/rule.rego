package cdk_preflight

import rego.v1

# count(ns) <= 63 only keeps the format check away from strings that are
# already too long to be a label; the rule is about the character set.
violation contains make_diag_full("pf-eks-addon-namespace-config-format", "ERROR", name,
	"Properties.NamespaceConfig.Namespace",
	sprintf("Namespace %v is not an RFC 1123 DNS label (\"Provided namespace value is not a valid RFC 1123 DNS label\")", [ns]),
	"Use lowercase letters, digits and hyphens, starting and ending with an alphanumeric",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-eks-addon-namespaceconfig.html") if {
	some name in resources_of_type("AWS::EKS::Addon")
	ns := _pf_ekslib_oget(_pf_ekslib_get(name, "NamespaceConfig"), "Namespace")
	_pf_ekslib_lit(ns)
	count(ns) <= 63
	not regex.match(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`, ns)
}
