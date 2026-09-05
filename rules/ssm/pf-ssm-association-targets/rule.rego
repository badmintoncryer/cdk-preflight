package cdk_preflight

import rego.v1

_pf_ssmat_url := "https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_CreateAssociation.html"

_pf_ssmat_fix := "Add Targets such as [{Key: tag:Env, Values: [prod]}] or [{Key: InstanceIds, Values: [\"*\"]}]"

_pf_ssmat_props(name) := props if {
	props := input.resources[name].properties
	is_object(props)
}

_pf_ssmat_targets(name) := t if {
	t := object.get(_pf_ssmat_props(name), "Targets", null)
	is_array(t)
	count(t) > 0
}

violation contains make_diag_full("pf-ssm-association-targets", "ERROR", name,
	"Properties.Targets",
	"neither InstanceId nor Targets is set; CreateAssociation fails with \"Instance ID or targets must be specified\"",
	_pf_ssmat_fix, _pf_ssmat_url) if {
	some name in resources_of_type("AWS::SSM::Association")
	_pf_ssmat_props(name)
	not _pf_ssmat_targets(name)
	object.get(_pf_ssmat_props(name), "InstanceId", "__pf_absent") == "__pf_absent"
}

_pf_ssmat_key_ok(k) if k in ["InstanceIds", "aws:NoOpAutomationTag", "tag-key"]

_pf_ssmat_key_ok(k) if lower(k) == "resource-groups:name"

_pf_ssmat_key_ok(k) if startswith(k, "tag:")

violation contains make_diag_full("pf-ssm-association-targets", "ERROR", name,
	sprintf("Properties.Targets.%d.Key", [i]),
	sprintf("target key '%s' is not supported; CreateAssociation fails with \"Unsupported target key: %s, can either be InstanceIds, aws:NoOpAutomationTag, resource-groups:name, tag-key or start with tag:\"", [k, k]),
	_pf_ssmat_fix, _pf_ssmat_url) if {
	some name in resources_of_type("AWS::SSM::Association")
	some i, _ in _pf_ssmat_targets(name)
	k := resolve(name, sprintf("Properties.Targets.%d.Key", [i]))
	is_string(k)
	not _pf_ssmat_key_ok(k)
}

violation contains make_diag_full("pf-ssm-association-targets", "ERROR", name,
	sprintf("Properties.Targets.%d.Values", [i]),
	"target Values contain an empty string (or nothing); CreateAssociation fails with \"Tag or InstanceIds values cannot contain null or empty string.\"",
	_pf_ssmat_fix, _pf_ssmat_url) if {
	some name in resources_of_type("AWS::SSM::Association")
	some i, _ in _pf_ssmat_targets(name)
	vals := flatten_list(name, sprintf("Properties.Targets.%d.Values", [i]))
	some e in vals
	e.value == ""
}

violation contains make_diag_full("pf-ssm-association-targets", "ERROR", name,
	sprintf("Properties.Targets.%d.Values", [i]),
	sprintf("'%s' is not an instance id (i-... / mi-... / *); CreateAssociation fails with \"Invalid InstanceId format: %s\"", [v, v]),
	_pf_ssmat_fix, _pf_ssmat_url) if {
	some name in resources_of_type("AWS::SSM::Association")
	some i, _ in _pf_ssmat_targets(name)
	resolve(name, sprintf("Properties.Targets.%d.Key", [i])) == "InstanceIds"
	some e in flatten_list(name, sprintf("Properties.Targets.%d.Values", [i]))
	v := e.value
	is_string(v)
	not regex.match("^(\\*|i-[0-9a-f]{8,17}|mi-[0-9a-f]{17})$", v)
}
