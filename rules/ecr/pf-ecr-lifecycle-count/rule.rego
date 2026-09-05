package cdk_preflight

import rego.v1

_pf_ecrlpc_url := "https://docs.aws.amazon.com/AmazonECR/latest/userguide/lifecycle_policy_parameters.html"

_pf_ecrlpc_fix := "Set countUnit: days only for sinceImagePushed / sinceImagePulled / sinceImageTransitioned, keep countNumber >= 1, and use storageClass archive only with sinceImageTransitioned"

_pf_ecrlpc_since := {"sinceImagePushed", "sinceImagePulled", "sinceImageTransitioned"}

_pf_ecrlpc_types := {"imageCountMoreThan", "sinceImagePushed", "sinceImagePulled", "sinceImageTransitioned"}

violation contains make_diag_full("pf-ecr-lifecycle-count", "ERROR", name,
	sprintf("%s[%d].selection.countType", [_pf_ecrlib_prop(name), i]),
	sprintf("countType is '%s'; PutLifecyclePolicy accepts imageCountMoreThan, sinceImagePushed, sinceImagePulled or sinceImageTransitioned", [ct]),
	_pf_ecrlpc_fix, _pf_ecrlpc_url) if {
	some [name, i, rule] in _pf_ecrlib_rules
	ct := object.get(_pf_ecrlib_selection(rule), "countType", null)
	is_string(ct)
	not ct in _pf_ecrlpc_types
}

violation contains make_diag_full("pf-ecr-lifecycle-count", "ERROR", name,
	sprintf("%s[%d].selection.countUnit", [_pf_ecrlib_prop(name), i]),
	sprintf("countUnit is set but countType is '%s'; PutLifecyclePolicy accepts countUnit only with the sinceImage* count types", [ct]),
	_pf_ecrlpc_fix, _pf_ecrlpc_url) if {
	some [name, i, rule] in _pf_ecrlib_rules
	sel := _pf_ecrlib_selection(rule)
	ct := object.get(sel, "countType", null)
	is_string(ct)
	not ct in _pf_ecrlpc_since
	not _pf_ecrlib_absent(sel, "countUnit")
}

violation contains make_diag_full("pf-ecr-lifecycle-count", "ERROR", name,
	sprintf("%s[%d].selection", [_pf_ecrlib_prop(name), i]),
	sprintf("countType is '%s' but countUnit is missing; PutLifecyclePolicy requires countUnit: days for the sinceImage* count types", [ct]),
	_pf_ecrlpc_fix, _pf_ecrlpc_url) if {
	some [name, i, rule] in _pf_ecrlib_rules
	sel := _pf_ecrlib_selection(rule)
	ct := object.get(sel, "countType", null)
	ct in _pf_ecrlpc_since
	_pf_ecrlib_absent(sel, "countUnit")
}

violation contains make_diag_full("pf-ecr-lifecycle-count", "ERROR", name,
	sprintf("%s[%d].selection.countUnit", [_pf_ecrlib_prop(name), i]),
	sprintf("countUnit is '%s'; days is the only accepted unit", [cu]),
	_pf_ecrlpc_fix, _pf_ecrlpc_url) if {
	some [name, i, rule] in _pf_ecrlib_rules
	cu := object.get(_pf_ecrlib_selection(rule), "countUnit", null)
	is_string(cu)
	cu != "days"
}

violation contains make_diag_full("pf-ecr-lifecycle-count", "ERROR", name,
	sprintf("%s[%d].selection.countNumber", [_pf_ecrlib_prop(name), i]),
	sprintf("countNumber is %d; PutLifecyclePolicy accepts positive integers only (0 is not accepted)", [cn]),
	_pf_ecrlpc_fix, _pf_ecrlpc_url) if {
	some [name, i, rule] in _pf_ecrlib_rules
	cn := object.get(_pf_ecrlib_selection(rule), "countNumber", null)
	is_number(cn)
	cn < 1
}

violation contains make_diag_full("pf-ecr-lifecycle-count", "ERROR", name,
	sprintf("%s[%d].selection.storageClass", [_pf_ecrlib_prop(name), i]),
	sprintf("storageClass is 'archive' but countType is '%s'; only sinceImageTransitioned selects archived images (\"SINCE_IMAGE_PUSHED, SINCE_IMAGE_PULLED and IMAGE_COUNT_MORE_THAN support the STANDARD storage class only\")", [ct]),
	_pf_ecrlpc_fix, _pf_ecrlpc_url) if {
	some [name, i, rule] in _pf_ecrlib_rules
	sel := _pf_ecrlib_selection(rule)
	object.get(sel, "storageClass", "") == "archive"
	ct := object.get(sel, "countType", null)
	is_string(ct)
	ct != "sinceImageTransitioned"
}
