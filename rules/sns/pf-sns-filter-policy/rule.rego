package cdk_preflight

import rego.v1

_pf_snsfp_url := "https://docs.aws.amazon.com/sns/latest/dg/sns-subscription-filter-policies.html"

_pf_snsfp_fix := "Keep the filter policy to 5 keys of non-empty arrays (or nested objects with FilterPolicyScope: MessageBody)"

_pf_snsfp_sub contains [name, "Properties", sub, topic] if {
	some name in resources_of_type("AWS::SNS::Subscription")
	sub := input.resources[name].properties
	is_object(sub)
	topic := resolve(name, "Properties.TopicArn")
	is_string(topic)
}

_pf_snsfp_sub contains [name, path, sub, name] if {
	some name in resources_of_type("AWS::SNS::Topic")
	some s in flatten_list(name, "Properties.Subscription")
	sub := s.value
	is_object(sub)
	path := sprintf("Properties.Subscription.%d", [s.index])
}

_pf_snsfp_proto(name, path) := p if {
	p := resolve(name, sprintf("%s.Protocol", [path]))
	is_string(p)
}

_pf_snsfp_pol(sub) := pol if {
	pol := object.get(sub, "FilterPolicy", null)
	is_object(pol)
}

_pf_snsfp_pol(sub) := pol if {
	raw := object.get(sub, "FilterPolicy", null)
	is_string(raw)
	pol := json.unmarshal(raw)
	is_object(pol)
}

_pf_snsfp_err := "Invalid parameter: Attributes Reason: FilterPolicy: "

violation contains make_diag_full("pf-sns-filter-policy", "ERROR", name,
	sprintf("%s.FilterPolicy", [path]),
	sprintf("FilterPolicy has %d keys (maximum 5); Subscribe fails with \"%sFilter policy can not have more than 5 keys\"", [n, _pf_snsfp_err]),
	_pf_snsfp_fix, _pf_snsfp_url) if {
	some [name, path, sub, _] in _pf_snsfp_sub
	n := count(object.keys(_pf_snsfp_pol(sub)))
	n > 5
}

violation contains make_diag_full("pf-sns-filter-policy", "ERROR", name,
	sprintf("%s.FilterPolicy.%s", [path, k]),
	sprintf("FilterPolicy key '%s' has a scalar value; each key takes an array of match values (or an object with FilterPolicyScope MessageBody), and Subscribe fails with \"%s\\\"%s\\\" must be an object or an array\"", [k, _pf_snsfp_err, k]),
	_pf_snsfp_fix, _pf_snsfp_url) if {
	some [name, path, sub, _] in _pf_snsfp_sub
	some k, v in _pf_snsfp_pol(sub)
	not is_array(v)
	not is_object(v)
}

violation contains make_diag_full("pf-sns-filter-policy", "ERROR", name,
	sprintf("%s.FilterPolicy.%s", [path, k]),
	sprintf("FilterPolicy key '%s' is an empty array; Subscribe fails with \"%sEmpty arrays are not allowed\"", [k, _pf_snsfp_err]),
	_pf_snsfp_fix, _pf_snsfp_url) if {
	some [name, path, sub, _] in _pf_snsfp_sub
	some k, v in _pf_snsfp_pol(sub)
	is_array(v)
	count(v) == 0
}

violation contains make_diag_full("pf-sns-filter-policy", "ERROR", name,
	sprintf("%s.FilterPolicy.%s", [path, k]),
	sprintf("FilterPolicy key '%s' has an array inside its array; Subscribe fails with \"%sMatch value must be String, number, true, false, or null\"", [k, _pf_snsfp_err]),
	_pf_snsfp_fix, _pf_snsfp_url) if {
	some [name, path, sub, _] in _pf_snsfp_sub
	some k, v in _pf_snsfp_pol(sub)
	is_array(v)
	some e in v
	is_array(e)
}

_pf_snsfp_attr_scope(sub) if object.get(sub, "FilterPolicyScope", "MessageAttributes") == "MessageAttributes"

violation contains make_diag_full("pf-sns-filter-policy", "ERROR", name,
	sprintf("%s.FilterPolicy.%s", [path, k]),
	sprintf("FilterPolicy key '%s' nests an object while FilterPolicyScope is MessageAttributes; Subscribe fails with \"Invalid parameter: Attributes Reason: Filter policy scope MessageAttributes does not support nested filter policy\"", [k]),
	_pf_snsfp_fix, _pf_snsfp_url) if {
	some [name, path, sub, _] in _pf_snsfp_sub
	_pf_snsfp_attr_scope(sub)
	some k, v in _pf_snsfp_pol(sub)
	is_object(v)
}

violation contains make_diag_full("pf-sns-filter-policy", "ERROR", name,
	sprintf("%s.FilterPolicyScope", [path]),
	sprintf("FilterPolicyScope '%s' is not MessageAttributes or MessageBody; Subscribe fails with \"Invalid parameter: Attributes Reason: FilterPolicyScope: Invalid value [%s]. Please use either MessageBody or MessageAttributes\"", [s, s]),
	_pf_snsfp_fix, _pf_snsfp_url) if {
	some [name, path, sub, _] in _pf_snsfp_sub
	s := resolve(name, sprintf("%s.FilterPolicyScope", [path]))
	is_string(s)
	not s in {"MessageAttributes", "MessageBody"}
}
