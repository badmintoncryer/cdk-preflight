package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-avp-oidc-requires-principal-entity-type", "ERROR", name, "Properties.PrincipalEntityType",
	"this identity source is OpenIdConnectConfiguration but sets no PrincipalEntityType; CreateIdentitySource answers \"Invalid PrincipalEntityType, must not be empty\" even though CloudFormation documents the property as optional",
	"Set PrincipalEntityType to the entity type the OIDC principals map to, e.g. MyApp::User",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-verifiedpermissions-identitysource.html") if {
	some name in resources_of_type("AWS::VerifiedPermissions::IdentitySource")
	props := input.resources[name].properties
	is_object(props)
	oidc := object.get(props, ["Configuration", "OpenIdConnectConfiguration"], null)
	is_object(oidc)

	# Issuer is mandatory on the OIDC configuration, so requiring it here is what
	# tells a real configuration apart from an Fn::If / Fn::GetAtt marker object.
	object.get(oidc, "Issuer", "__pf_absent") != "__pf_absent"
	object.get(props, "PrincipalEntityType", "__pf_absent") == "__pf_absent"
}
