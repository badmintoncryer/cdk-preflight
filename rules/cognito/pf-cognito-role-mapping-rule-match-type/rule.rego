package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-role-mapping-rule-match-type", "ERROR", name,
	sprintf("Properties.RoleMappings.%s.RulesConfiguration.Rules", [k]),
	sprintf("role mapping '%s' has MatchType '%v'; the roles call fails with \"Member must satisfy enum value set: [StartsWith, Equals, Contains, NotEqual]\"", [k, mt]),
	"Use one of Equals, Contains, StartsWith, NotEqual",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-identitypoolroleattachment.html") if {
	some name in resources_of_type("AWS::Cognito::IdentityPoolRoleAttachment")
	rm := resolve(name, "Properties.RoleMappings")
	is_object(rm)
	some k, v in rm
	rules := _pf_coglib_at2(v, "RulesConfiguration", "Rules")
	is_array(rules)
	some r in rules
	mt := _pf_coglib_at(r, "MatchType")
	is_string(mt)
	not mt in {"Equals", "Contains", "StartsWith", "NotEqual"}
}
