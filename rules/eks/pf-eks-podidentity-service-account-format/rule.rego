package cdk_preflight

import rego.v1

# The service quotes the regex back; a dotted name is legal here and is not
# for the namespace, which is why the two rules carry different patterns.
violation contains make_diag_full("pf-eks-podidentity-service-account-format", "ERROR", name,
	"Properties.ServiceAccount",
	sprintf("ServiceAccount %v is not a DNS-1123 subdomain (\"The parameter serviceAccount contains invalid characters.\")", [sa]),
	"Use lowercase letters, digits, hyphens and dots, with every dot-separated label starting and ending alphanumeric",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-eks-podidentityassociation.html") if {
	some name in resources_of_type("AWS::EKS::PodIdentityAssociation")
	sa := resolve(name, "Properties.ServiceAccount")
	_pf_ekslib_lit(sa)
	not regex.match(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`, sa)
}
