package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-idp-identifiers-max", "ERROR", name,
	"Properties.IdpIdentifiers",
	sprintf("the provider has %d IdpIdentifiers; the provider create fails with \"Member must have length less than or equal to 50\"", [count(ids)]),
	"Keep IdpIdentifiers at 50 entries or fewer",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpoolidentityprovider.html") if {
	some name in resources_of_type("AWS::Cognito::UserPoolIdentityProvider")
	ids := flatten_list(name, "Properties.IdpIdentifiers")
	count(ids) > 50
}
