package cdk_preflight

import rego.v1

_pf_ecrlts_url := "https://docs.aws.amazon.com/AmazonECR/latest/userguide/lifecycle_policy_parameters.html"

_pf_ecrlts_fix := "Use tagStatus=tagged with either tagPrefixList or tagPatternList (not both), and leave both out for untagged / any; a tag pattern may hold at most four wildcards"

_pf_ecrlts_list(sel, key) := v if {
	v := object.get(sel, key, null)
	is_array(v)
}

_pf_ecrlts_has(sel, key) if count(_pf_ecrlts_list(sel, key)) > 0

violation contains make_diag_full("pf-ecr-lifecycle-tag-status", "ERROR", name,
	sprintf("%s[%d].selection", [_pf_ecrlib_prop(name), i]),
	sprintf("rule %d has tagStatus=tagged but neither tagPrefixList nor tagPatternList; PutLifecyclePolicy fails with \"Must specify tagPrefixList or tagPatternList\"", [i]),
	_pf_ecrlts_fix, _pf_ecrlts_url) if {
	some [name, i, rule] in _pf_ecrlib_rules
	sel := _pf_ecrlib_selection(rule)
	object.get(sel, "tagStatus", "") == "tagged"
	not _pf_ecrlts_has(sel, "tagPrefixList")
	not _pf_ecrlts_has(sel, "tagPatternList")
}

violation contains make_diag_full("pf-ecr-lifecycle-tag-status", "ERROR", name,
	sprintf("%s[%d].selection", [_pf_ecrlib_prop(name), i]),
	sprintf("rule %d sets both tagPrefixList and tagPatternList; PutLifecyclePolicy fails with \"If policy has a tagged rule, it must specify only one of tagPrefixList or tagPatternList\"", [i]),
	_pf_ecrlts_fix, _pf_ecrlts_url) if {
	some [name, i, rule] in _pf_ecrlib_rules
	sel := _pf_ecrlib_selection(rule)
	_pf_ecrlts_has(sel, "tagPrefixList")
	_pf_ecrlts_has(sel, "tagPatternList")
}

violation contains make_diag_full("pf-ecr-lifecycle-tag-status", "ERROR", name,
	sprintf("%s[%d].selection.%s", [_pf_ecrlib_prop(name), i, key]),
	sprintf("rule %d has tagStatus=%s but sets %s; PutLifecyclePolicy fails with \"Cannot specify %s with tagStatus %s\"", [i, st, key, key, st]),
	_pf_ecrlts_fix, _pf_ecrlts_url) if {
	some [name, i, rule] in _pf_ecrlib_rules
	sel := _pf_ecrlib_selection(rule)
	st := object.get(sel, "tagStatus", "")
	st in {"untagged", "any"}
	some key in ["tagPrefixList", "tagPatternList"]
	_pf_ecrlts_has(sel, key)
}

violation contains make_diag_full("pf-ecr-lifecycle-tag-status", "ERROR", name,
	sprintf("%s[%d].selection.tagPatternList", [_pf_ecrlib_prop(name), i]),
	sprintf("tag pattern '%s' holds %d wildcards; PutLifecyclePolicy allows at most four per pattern (\"Invalid tag pattern provided\")", [p, count(regex.find_n("\\*", p, -1))]),
	_pf_ecrlts_fix, _pf_ecrlts_url) if {
	some [name, i, rule] in _pf_ecrlib_rules
	some p in _pf_ecrlts_list(_pf_ecrlib_selection(rule), "tagPatternList")
	is_string(p)
	count(regex.find_n("\\*", p, -1)) > 4
}

violation contains make_diag_full("pf-ecr-lifecycle-tag-status", "ERROR", name,
	sprintf("%s[%d].selection.tagStatus", [_pf_ecrlib_prop(name), i]),
	sprintf("tagStatus is '%s'; PutLifecyclePolicy accepts tagged, untagged or any", [st]),
	_pf_ecrlts_fix, _pf_ecrlts_url) if {
	some [name, i, rule] in _pf_ecrlib_rules
	st := object.get(_pf_ecrlib_selection(rule), "tagStatus", null)
	is_string(st)
	not st in {"tagged", "untagged", "any"}
}
