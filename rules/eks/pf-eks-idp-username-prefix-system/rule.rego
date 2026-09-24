package cdk_preflight

import rego.v1

# Only the exact "system:" is claimed: that is what the service was measured
# rejecting, and whether it also refuses "system:foo" is unproven.
violation contains make_diag_full("pf-eks-idp-username-prefix-system", "ERROR", name,
	"Properties.Oidc.UsernamePrefix",
	"UsernamePrefix is \"system:\", which Kubernetes reserves (\"The prefix system: is reserved for Kubernetes system use\")",
	"Use a prefix of your own, e.g. okta:",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-eks-identityproviderconfig-oidcidentityproviderconfig.html") if {
	some name in resources_of_type("AWS::EKS::IdentityProviderConfig")
	resolve(name, "Properties.Oidc.UsernamePrefix") == "system:"
}
