package cdk_preflight

import rego.v1

_pf_wafdp_url := "https://docs.aws.amazon.com/waf/latest/APIReference/API_FieldToProtect.html"

_pf_wafdp_fix := "Name the headers / cookies / query arguments in FieldKeys for SINGLE_* field types, omit FieldKeys for QUERY_STRING and BODY, and list each field type once"

_pf_wafdp contains [name, k, d] if {
	some name in resources_of_type("AWS::WAFv2::WebACL")
	dps := input.resources[name].properties.DataProtectionConfig.DataProtections
	some k
	d := dps[k]
	is_object(d)
}

_pf_wafdp_path(k) := sprintf("Properties.DataProtectionConfig.DataProtections[%d].Field", [k])

_pf_wafdp_nkeys(d) := count(d.Field.FieldKeys) if is_array(d.Field.FieldKeys)

_pf_wafdp_nkeys(d) := 0 if not is_array(object.get(d.Field, "FieldKeys", null))

violation contains make_diag_full("pf-wafv2-data-protection", "ERROR", name, _pf_wafdp_path(k),
	sprintf("%s needs FieldKeys naming the fields to protect; the create call fails with \"FieldKeys cannot be null or empty for %s type\"", [ft, ft]),
	_pf_wafdp_fix, _pf_wafdp_url) if {
	some [name, k, d] in _pf_wafdp
	ft := d.Field.FieldType
	ft in {"SINGLE_HEADER", "SINGLE_COOKIE", "SINGLE_QUERY_ARGUMENT"}
	_pf_wafdp_nkeys(d) == 0
}

violation contains make_diag_full("pf-wafv2-data-protection", "ERROR", name, _pf_wafdp_path(k),
	sprintf("%s protects the whole component and takes no FieldKeys; the create call fails with \"Your request in not valid.\"", [ft]),
	_pf_wafdp_fix, _pf_wafdp_url) if {
	some [name, k, d] in _pf_wafdp
	ft := d.Field.FieldType
	ft in {"QUERY_STRING", "BODY"}
	_pf_wafdp_nkeys(d) > 0
}

violation contains make_diag_full("pf-wafv2-data-protection", "ERROR", name, _pf_wafdp_path(m),
	sprintf("field type %s is already configured at DataProtections[%d]; the create call fails with \"The field has already been specified for %s\"", [ft, k, ft]),
	_pf_wafdp_fix, _pf_wafdp_url) if {
	some [name, k, d] in _pf_wafdp
	some [nm, m, d2] in _pf_wafdp
	nm == name
	k < m
	ft := d.Field.FieldType
	d2.Field.FieldType == ft
}
