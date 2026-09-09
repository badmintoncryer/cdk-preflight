package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-role-mappings-token-no-rules", "ERROR", name,
	sprintf("Properties.RoleMappings.%s.RulesConfiguration", [k]),
	sprintf("role mapping '%s' is Type Token but carries a RulesConfiguration; the roles call rejects the mapping", [k]),
	"Set Type to Rules, or drop RulesConfiguration",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-identitypoolroleattachment.html") if {
	some name in resources_of_type("AWS::Cognito::IdentityPoolRoleAttachment")
	rm := resolve(name, "Properties.RoleMappings")
	is_object(rm)
	some k, v in rm
	_pf_coglib_at(v, "Type") == "Token"
	_pf_coglib_set(_pf_coglib_at(v, "RulesConfiguration"))
}
