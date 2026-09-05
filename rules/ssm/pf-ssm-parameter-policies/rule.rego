package cdk_preflight

import rego.v1

_pf_ssmpp_url := "https://docs.aws.amazon.com/systems-manager/latest/userguide/parameter-store-policies.html"

_pf_ssmpp_fix := "Write Policies as a JSON array of Expiration / ExpirationNotification / NoChangeNotification objects with Version \"1.0\" and the documented Attributes"

_pf_ssmpp_raw(name) := v if {
	v := object.get(input.resources[name].properties, "Policies", null)
	v != null
}

_pf_ssmpp_list(name) := pol if {
	raw := _pf_ssmpp_raw(name)
	is_string(raw)
	json.is_valid(raw)
	pol := json.unmarshal(raw)
	is_array(pol)
}

_pf_ssmpp_list(name) := pol if {
	pol := _pf_ssmpp_raw(name)
	is_array(pol)
}

violation contains make_diag_full("pf-ssm-parameter-policies", "ERROR", name,
	"Properties.Policies",
	"Policies is not a JSON array; PutParameter fails with \"Invalid policies input\"",
	_pf_ssmpp_fix, _pf_ssmpp_url) if {
	some name in resources_of_type("AWS::SSM::Parameter")
	raw := _pf_ssmpp_raw(name)
	is_string(raw)
	not _pf_ssmpp_list(name)
}

violation contains make_diag_full("pf-ssm-parameter-policies", "ERROR", name,
	"Properties.Policies",
	sprintf("%d policies are attached; PutParameter fails with \"Number of policies attached to a parameter cannot exceed 10\"", [count(pol)]),
	_pf_ssmpp_fix, _pf_ssmpp_url) if {
	some name in resources_of_type("AWS::SSM::Parameter")
	pol := _pf_ssmpp_list(name)
	count(pol) > 10
}

_pf_ssmpp_types := ["Expiration", "ExpirationNotification", "NoChangeNotification"]

violation contains make_diag_full("pf-ssm-parameter-policies", "ERROR", name,
	sprintf("Properties.Policies.%d.Type", [i]),
	sprintf("policy Type '%v' is not Expiration, ExpirationNotification or NoChangeNotification (case-sensitive); PutParameter fails with \"Policy type %v is not supported.\"", [t, t]),
	_pf_ssmpp_fix, _pf_ssmpp_url) if {
	some name in resources_of_type("AWS::SSM::Parameter")
	some i, p in _pf_ssmpp_list(name)
	is_object(p)
	t := object.get(p, "Type", "")
	not t in _pf_ssmpp_types
}

violation contains make_diag_full("pf-ssm-parameter-policies", "ERROR", name,
	sprintf("Properties.Policies.%d.Version", [i]),
	sprintf("policy Version '%v' is not \"1.0\"; PutParameter fails with \"Unsupported policy version.\"", [v]),
	_pf_ssmpp_fix, _pf_ssmpp_url) if {
	some name in resources_of_type("AWS::SSM::Parameter")
	some i, p in _pf_ssmpp_list(name)
	is_object(p)
	v := object.get(p, "Version", "")
	v != "1.0"
}

violation contains make_diag_full("pf-ssm-parameter-policies", "ERROR", name,
	sprintf("Properties.Policies.%d.Attributes", [i]),
	"policy has no Attributes object; PutParameter fails with \"Mandatory policy attribute Attributes is missing.\"",
	_pf_ssmpp_fix, _pf_ssmpp_url) if {
	some name in resources_of_type("AWS::SSM::Parameter")
	some i, p in _pf_ssmpp_list(name)
	is_object(p)
	object.get(p, "Type", "") in _pf_ssmpp_types
	not is_object(object.get(p, "Attributes", null))
}

_pf_ssmpp_attrs(p) := a if {
	a := object.get(p, "Attributes", null)
	is_object(a)
}

_pf_ssmpp_of(name, t) := [p | some p in _pf_ssmpp_list(name); is_object(p); object.get(p, "Type", "") == t]

violation contains make_diag_full("pf-ssm-parameter-policies", "ERROR", name,
	"Properties.Policies",
	"more than one Expiration policy is attached; PutParameter fails with \"There can be only one expiration policy\"",
	_pf_ssmpp_fix, _pf_ssmpp_url) if {
	some name in resources_of_type("AWS::SSM::Parameter")
	count(_pf_ssmpp_of(name, "Expiration")) > 1
}

violation contains make_diag_full("pf-ssm-parameter-policies", "ERROR", name,
	sprintf("Properties.Policies.%d.Attributes.Timestamp", [i]),
	"Expiration policy has no Timestamp; PutParameter fails with \"A valid Expiration policy must have an attribute of Timestamp.\"",
	_pf_ssmpp_fix, _pf_ssmpp_url) if {
	some name in resources_of_type("AWS::SSM::Parameter")
	some i, p in _pf_ssmpp_list(name)
	is_object(p)
	object.get(p, "Type", "") == "Expiration"
	a := _pf_ssmpp_attrs(p)
	object.get(a, "Timestamp", "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-ssm-parameter-policies", "ERROR", name,
	sprintf("Properties.Policies.%d.Attributes.Timestamp", [i]),
	sprintf("Expiration Timestamp '%v' is not an ISO-8601 date-time (e.g. 2030-01-01T00:00:00.000Z); PutParameter fails with \"Invalid timestamp format\"", [ts]),
	_pf_ssmpp_fix, _pf_ssmpp_url) if {
	some name in resources_of_type("AWS::SSM::Parameter")
	some i, p in _pf_ssmpp_list(name)
	is_object(p)
	object.get(p, "Type", "") == "Expiration"
	ts := object.get(_pf_ssmpp_attrs(p), "Timestamp", null)
	ts != null
	not _pf_ssmpp_iso(ts)
}

_pf_ssmpp_iso(ts) if {
	is_string(ts)
	regex.match("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}(:[0-9]{2}(\\.[0-9]+)?)?(Z|[+-][0-9]{2}:[0-9]{2})$", ts)
}

violation contains make_diag_full("pf-ssm-parameter-policies", "ERROR", name,
	"Properties.Policies",
	"an ExpirationNotification policy is attached without an Expiration policy; PutParameter fails with \"Expiration notification policies are missing expiration policy\"",
	_pf_ssmpp_fix, _pf_ssmpp_url) if {
	some name in resources_of_type("AWS::SSM::Parameter")
	count(_pf_ssmpp_of(name, "ExpirationNotification")) > 0
	count(_pf_ssmpp_of(name, "Expiration")) == 0
}

_pf_ssmpp_required := {"ExpirationNotification": ["Before", "Unit"], "NoChangeNotification": ["After", "Unit"]}

violation contains make_diag_full("pf-ssm-parameter-policies", "ERROR", name,
	sprintf("Properties.Policies.%d.Attributes.%s", [i, k]),
	sprintf("%s policy has no %s attribute; PutParameter fails with \"Mandatory policy attribute %s is missing.\"", [t, k, k]),
	_pf_ssmpp_fix, _pf_ssmpp_url) if {
	some name in resources_of_type("AWS::SSM::Parameter")
	some i, p in _pf_ssmpp_list(name)
	is_object(p)
	t := object.get(p, "Type", "")
	some k in _pf_ssmpp_required[t]
	a := _pf_ssmpp_attrs(p)
	object.get(a, k, "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-ssm-parameter-policies", "ERROR", name,
	sprintf("Properties.Policies.%d.Attributes.%s", [i, k]),
	sprintf("%s '%v' is not a positive integer; PutParameter fails with \"Attribute %s must be a positive integer.\"", [k, v, k]),
	_pf_ssmpp_fix, _pf_ssmpp_url) if {
	some name in resources_of_type("AWS::SSM::Parameter")
	some i, p in _pf_ssmpp_list(name)
	is_object(p)
	t := object.get(p, "Type", "")
	some k in ["Before", "After"]
	k in _pf_ssmpp_required[t]
	v := object.get(_pf_ssmpp_attrs(p), k, null)
	v != null
	not _pf_ssmpp_positive(v)
}

_pf_ssmpp_positive(v) if {
	is_number(v)
	v >= 1
	v == floor(v)
}

_pf_ssmpp_positive(v) if {
	is_string(v)
	regex.match("^[1-9][0-9]*$", v)
}

violation contains make_diag_full("pf-ssm-parameter-policies", "ERROR", name,
	sprintf("Properties.Policies.%d.Attributes.Unit", [i]),
	sprintf("Unit '%v' is neither Days nor Hours; PutParameter fails with \"Supported time units: DAYS HOURS\"", [u]),
	_pf_ssmpp_fix, _pf_ssmpp_url) if {
	some name in resources_of_type("AWS::SSM::Parameter")
	some i, p in _pf_ssmpp_list(name)
	is_object(p)
	object.get(p, "Type", "") in ["ExpirationNotification", "NoChangeNotification"]
	u := object.get(_pf_ssmpp_attrs(p), "Unit", null)
	u != null
	not _pf_ssmpp_unit(u)
}

_pf_ssmpp_unit(u) if {
	is_string(u)
	lower(u) in ["days", "hours"]
}
