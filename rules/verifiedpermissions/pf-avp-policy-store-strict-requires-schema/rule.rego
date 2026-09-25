package cdk_preflight

import rego.v1

# The STRICT policy stores that a Policy or a PolicyTemplate in this same
# template points at with a Ref. A store nothing references is fine as it is:
# Verified Permissions creates it, and only the policies are rejected.
_pf_avpstrict_store(name) := store if {
	store := resolve(name, "Properties.PolicyStoreId")
	is_string(store)
	store in resources_of_type("AWS::VerifiedPermissions::PolicyStore")
	resolve(store, "Properties.ValidationSettings.Mode") == "STRICT"
}

_pf_avpstrict_users contains store if {
	some name in resources_of_type("AWS::VerifiedPermissions::Policy")
	store := _pf_avpstrict_store(name)
}

_pf_avpstrict_users contains store if {
	some name in resources_of_type("AWS::VerifiedPermissions::PolicyTemplate")
	store := _pf_avpstrict_store(name)
}

violation contains make_diag_full("pf-avp-policy-store-strict-requires-schema", "ERROR", store, "Properties.ValidationSettings.Mode",
	"ValidationSettings.Mode is STRICT and this policy store carries no schema, so every policy and policy template pointing at it is rejected with \"No schema present - automatically failing all validation.\"",
	"Set Schema.CedarJson to a schema declaring at least one action, or use Mode: OFF",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-verifiedpermissions-policystore-validationsettings.html") if {
	some store in _pf_avpstrict_users
	props := input.resources[store].properties
	is_object(props)
	object.get(props, "Schema", "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-avp-policy-store-strict-requires-schema", "ERROR", store, "Properties.ValidationSettings.Mode",
	"ValidationSettings.Mode is STRICT and this policy store's schema declares no actions, so every policy and policy template pointing at it is rejected with \"unable to find an applicable action given the policy scope constraints\"",
	"Set Schema.CedarJson to a schema declaring at least one action, or use Mode: OFF",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-verifiedpermissions-policystore-validationsettings.html") if {
	some store in _pf_avpstrict_users
	some [s2, _] in _pf_avpsch_parsed
	s2 == store
	declared := {a |
		some [s3, _, a, _] in _pf_avpsch_acts
		s3 == store
	}
	count(declared) == 0
}
