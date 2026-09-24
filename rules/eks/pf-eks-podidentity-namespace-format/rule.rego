package cdk_preflight

import rego.v1

# The service quotes this exact regex back in the error, so the rule is a
# transcription of it rather than an interpretation of a doc sentence.
violation contains make_diag_full("pf-eks-podidentity-namespace-format", "ERROR", name,
	"Properties.Namespace",
	sprintf("Namespace %v is not a DNS-1123 label (\"The parameter namespace contains invalid characters. It should conform to the regular expression \\\"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$\\\"\")", [ns]),
	"Use lowercase letters, digits and hyphens, starting and ending with a letter or digit",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-eks-podidentityassociation.html") if {
	some name in resources_of_type("AWS::EKS::PodIdentityAssociation")
	ns := resolve(name, "Properties.Namespace")
	_pf_ekslib_lit(ns)
	not regex.match(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`, ns)
}
