package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-avp-policy-scope-matches-applies-to", "ERROR", name, path,
	sprintf("the policy scope pins %v to %v, which is not in %v of action %v::Action::\"%v\"; ValidationSettings.Mode is STRICT, so CreatePolicy answers \"unable to find an applicable action given the policy scope constraints\"", [slot, et, key, ans, aid]),
	"Pin the scope to a type the action's appliesTo lists, or widen appliesTo in the schema",
	"https://docs.cedarpolicy.com/policies/validation.html") if {
	some [name, path, s, store] in _pf_avpsch_strict
	uids := regex.find_all_string_submatch_n(_pf_avpsch_actionuid, _pf_cedarlib_nocomment(s), -1)
	count(uids) == 1
	count(regex.find_n(`::Action::""`, _pf_cedarlib_code(s), -1)) == 1
	ans := uids[0][1]
	aid := uids[0][2]
	some [s2, ans2, aid2, d] in _pf_avpsch_acts
	s2 == store
	ans2 == ans
	aid2 == aid
	ap := object.get(d, "appliesTo", null)
	is_object(ap)
	some [slot, key] in {["principal", "principalTypes"], ["resource", "resourceTypes"]}
	types := object.get(ap, key, null)
	is_array(types)
	some part in _pf_cedarlib_parts(s)

	# `==` only. `principal in MyApp::Group::"g"` is legal against a
	# principalTypes of ["User"], because the group holds Users.
	pin := regex.find_all_string_submatch_n(sprintf(`^\s*%v\s*==\s*([A-Za-z_][A-Za-z_0-9]*(?:::[A-Za-z_][A-Za-z_0-9]*)*)::""\s*$`, [slot]), part, 1)
	count(pin) == 1
	et := pin[0][1]
	allowed := {e | some e in types; is_string(e)} | {sprintf("%v::%v", [ans, e]) |
		some e in types
		is_string(e)
		not contains(e, "::")
	}
	not et in allowed
}
