package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-role-attachment-roles-keys", "ERROR", name,
	sprintf("Properties.Roles.%s", [k]),
	sprintf("Roles has the key '%s'; SetIdentityPoolRoles only takes authenticated and unauthenticated", [k]),
	"Use the keys authenticated and/or unauthenticated",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-identitypoolroleattachment.html") if {
	some name in resources_of_type("AWS::Cognito::IdentityPoolRoleAttachment")
	roles := resolve(name, "Properties.Roles")
	is_object(roles)
	some k, _ in roles
	not k in {"authenticated", "unauthenticated"}
}
