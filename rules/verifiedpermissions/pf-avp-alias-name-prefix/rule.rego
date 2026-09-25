package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-avp-alias-name-prefix", "ERROR", name, "Properties.AliasName",
	sprintf("AliasName %v does not start with \"policy-store-alias/\"; CreatePolicyStoreAlias answers \"Invalid format.\"", [a]),
	"Prefix the alias with policy-store-alias/, e.g. policy-store-alias/my-alias",
	"https://docs.aws.amazon.com/verifiedpermissions/latest/apireference/API_CreatePolicyStoreAlias.html") if {
	some name in resources_of_type("AWS::VerifiedPermissions::PolicyStoreAlias")
	a := resolve(name, "Properties.AliasName")
	is_string(a)
	not input.resources[a]
	not startswith(a, "policy-store-alias/")
}
