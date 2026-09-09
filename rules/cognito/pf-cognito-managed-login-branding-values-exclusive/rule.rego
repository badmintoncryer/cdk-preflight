package cdk_preflight

import rego.v1

# Assets alongside UseCognitoProvidedValues are accepted (measured 2026-09-08);
# only Settings is exclusive with it.

violation contains make_diag_full("pf-cognito-managed-login-branding-values-exclusive", "ERROR", name,
	"Properties.Settings",
	"UseCognitoProvidedValues is true together with Settings; the branding create fails with \"useCognitoProvidedValues or settings should be specified (but not both)\"",
	"Either keep UseCognitoProvidedValues: true alone, or drop it and supply your own Settings",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-managedloginbranding.html") if {
	some name in resources_of_type("AWS::Cognito::ManagedLoginBranding")
	resolve(name, "Properties.UseCognitoProvidedValues") == true
	_pf_coglib_set(_pf_coglib_g1(name, "Settings"))
}
