package cdk_preflight

import rego.v1

# Shared helpers for the Cognito rules (rules/cognito/pf-cognito-*).
# Loaded ahead of every rule (BUNDLED_LIBS); never emits diagnostics.
#
# Absence has to be proven against the preprocessed document rather than read
# through resolve(), which is also undefined for values it cannot resolve
# (see AGENTS.md). The g1/g2/g3 getters walk a fixed depth - the engine's Rego
# has no walk builtin and forbids recursion - and return the sentinel
# "__pf_absent" when any level is missing.

_pf_coglib_obj(v) := v if is_object(v)

_pf_coglib_obj(v) := {} if not is_object(v)

_pf_coglib_props(name) := _pf_coglib_obj(input.resources[name].properties)

_pf_coglib_g1(name, a) := object.get(_pf_coglib_props(name), a, "__pf_absent")

_pf_coglib_g2(name, a, b) := object.get(_pf_coglib_obj(_pf_coglib_g1(name, a)), b, "__pf_absent")

_pf_coglib_g3(name, a, b, c) := object.get(_pf_coglib_obj(_pf_coglib_g2(name, a, b)), c, "__pf_absent")

_pf_coglib_absent(v) if v == "__pf_absent"

# A getter result that is really a string (the absence sentinel is one too).
_pf_coglib_str(v) := v if {
	is_string(v)
	v != "__pf_absent"
}

_pf_coglib_set(v) if v != "__pf_absent"

# Sub-object of an item pulled out of flatten_list, with the same sentinel.
_pf_coglib_at(o, a) := object.get(_pf_coglib_obj(o), a, "__pf_absent")

_pf_coglib_at2(o, a, b) := object.get(_pf_coglib_obj(_pf_coglib_at(o, a)), b, "__pf_absent")

_pf_coglib_arn_part(arn, i) := p if {
	is_string(arn)
	startswith(arn, "arn:")
	parts := split(arn, ":")
	count(parts) >= 6
	p := parts[i]
	p != ""
}

_pf_coglib_arn_service(arn) := _pf_coglib_arn_part(arn, 2)

_pf_coglib_arn_region(arn) := _pf_coglib_arn_part(arn, 3)

_pf_coglib_arn_account(arn) := _pf_coglib_arn_part(arn, 4)

# The user pool attributes every pool has, with the data type the service
# fixes for each; a Schema entry may re-declare one but not retype it.
_pf_coglib_std_attr_types := {
	"address": "String",
	"birthdate": "String",
	"email": "String",
	"email_verified": "Boolean",
	"family_name": "String",
	"gender": "String",
	"given_name": "String",
	"locale": "String",
	"middle_name": "String",
	"name": "String",
	"nickname": "String",
	"phone_number": "String",
	"phone_number_verified": "Boolean",
	"picture": "String",
	"preferred_username": "String",
	"profile": "String",
	"sub": "String",
	"updated_at": "Number",
	"website": "String",
	"zoneinfo": "String",
}

_pf_coglib_std_attrs := object.keys(_pf_coglib_std_attr_types)

# Custom attributes only: the ones that count against the 50 attribute cap.
_pf_coglib_custom_attrs(name) := [a |
	some a in flatten_list(name, "Properties.Schema")
	is_object(a.value)
	n := object.get(a.value, "Name", "")
	not n in _pf_coglib_std_attrs
]

_pf_coglib_std_scopes := {"openid", "email", "phone", "profile", "aws.cognito.signin.user.admin"}

# SES identities are only reachable from Cognito in these three regions -
# this is a fixed allowlist, not "the deploy region" (measured 2026-09-08).
_pf_coglib_ses_regions := {"eu-west-1", "us-east-1", "us-west-2"}

_pf_coglib_social_idps := {"Google", "Facebook", "LoginWithAmazon", "SignInWithApple"}
