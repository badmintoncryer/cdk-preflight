package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-avp-policy-action-in-schema", "ERROR", name, path,
	sprintf("the policy scope names action %v::Action::\"%v\", which policy store %v does not declare; ValidationSettings.Mode is STRICT, so CreatePolicy answers \"unrecognized action\"", [g[1], g[2], store]),
	"Name an action the schema's actions map declares, qualified with its namespace",
	"https://docs.cedarpolicy.com/policies/validation.html") if {
	some [name, path, s, store] in _pf_avpsch_strict
	uids := regex.find_all_string_submatch_n(_pf_avpsch_actionuid, _pf_cedarlib_nocomment(s), -1)

	# An action UID spelled inside a string literal is not a reference. The
	# normalized text has collapsed every literal to "", so the two counts
	# only agree when every match above sits in code.
	count(uids) == count(regex.find_n(`::Action::""`, _pf_cedarlib_code(s), -1))
	some g in uids
	not [store, g[1], g[2]] in _pf_avpsch_actids
}
