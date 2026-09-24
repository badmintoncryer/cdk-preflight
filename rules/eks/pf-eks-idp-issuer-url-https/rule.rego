package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-eks-idp-issuer-url-https", "ERROR", name,
	"Properties.Oidc.IssuerUrl",
	sprintf("IssuerUrl %v does not use https (\"IssuerURL must use https:// scheme.\")", [u]),
	"Point IssuerUrl at the https:// issuer of the OIDC provider",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-eks-identityproviderconfig-oidcidentityproviderconfig.html") if {
	some name in resources_of_type("AWS::EKS::IdentityProviderConfig")
	u := resolve(name, "Properties.Oidc.IssuerUrl")
	_pf_ekslib_lit(u)
	not startswith(u, "https://")
}
