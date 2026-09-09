package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-role-mappings-rules-required", "ERROR", name,
	sprintf("Properties.RoleMappings.%s.RulesConfiguration", [k]),
	sprintf("role mapping '%s' is Type Rules with no RulesConfiguration; the roles call rejects the mapping", [k]),
	"Add RulesConfiguration.Rules, or set Type to Token",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-identitypoolroleattachment.html") if {
	some name in resources_of_type("AWS::Cognito::IdentityPoolRoleAttachment")
	rm := resolve(name, "Properties.RoleMappings")
	is_object(rm)
	some k, v in rm
	_pf_coglib_at(v, "Type") == "Rules"
	_pf_coglib_absent(_pf_coglib_at(v, "RulesConfiguration"))
}
