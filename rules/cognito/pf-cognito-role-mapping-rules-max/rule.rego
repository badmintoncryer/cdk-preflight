package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-role-mapping-rules-max", "ERROR", name,
	sprintf("Properties.RoleMappings.%s.RulesConfiguration.Rules", [k]),
	sprintf("role mapping '%s' has %d rules; the roles call fails with \"The number of rules in the request exceeded 25.\"", [k, count(rules)]),
	"Keep each RulesConfiguration.Rules list at 25 entries or fewer",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-identitypoolroleattachment.html") if {
	some name in resources_of_type("AWS::Cognito::IdentityPoolRoleAttachment")
	rm := resolve(name, "Properties.RoleMappings")
	is_object(rm)
	some k, v in rm
	rules := _pf_coglib_at2(v, "RulesConfiguration", "Rules")
	is_array(rules)
	count(rules) > 25
}
