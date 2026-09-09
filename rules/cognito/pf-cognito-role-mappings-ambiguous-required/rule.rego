package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-role-mappings-ambiguous-required", "ERROR", name,
	sprintf("Properties.RoleMappings.%s.AmbiguousRoleResolution", [k]),
	sprintf("role mapping '%s' is Type %v with no AmbiguousRoleResolution; the roles call rejects the mapping", [k, t]),
	"Set AmbiguousRoleResolution to AuthenticatedRole or Deny",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-identitypoolroleattachment.html") if {
	some name in resources_of_type("AWS::Cognito::IdentityPoolRoleAttachment")
	rm := resolve(name, "Properties.RoleMappings")
	is_object(rm)
	some k, v in rm
	t := _pf_coglib_at(v, "Type")
	t in {"Token", "Rules"}
	_pf_coglib_absent(_pf_coglib_at(v, "AmbiguousRoleResolution"))
}
