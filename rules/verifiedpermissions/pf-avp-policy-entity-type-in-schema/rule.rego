package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-avp-policy-entity-type-in-schema", "ERROR", name, path,
	sprintf("the policy scope names entity type %v, which policy store %v does not declare; ValidationSettings.Mode is STRICT, so CreatePolicy answers \"unrecognized entity type `%v`\"", [et, store, et]),
	"Name an entity type the schema declares, qualified with its namespace",
	"https://docs.cedarpolicy.com/policies/validation.html") if {
	some [name, path, s, store] in _pf_avpsch_strict
	some part in _pf_cedarlib_parts(s)
	_pf_cedarlib_word(part) in {"principal", "resource"}
	some tok in _pf_cedarlib_paths(part)
	endswith(tok, `::""`)
	et := substring(tok, 0, count(tok) - 4)
	declared := {sprintf("%v::%v", [n2, t]) |
		some [s2, n2, t, _] in _pf_avpsch_ets
		s2 == store
	}
	not et in declared
}
