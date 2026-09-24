package cdk_preflight

import rego.v1

# Shared helpers for the CloudTrail rules (rules/cloudtrail/*). Loaded ahead of
# every rule (BUNDLED_LIBS); never emits diagnostics.
#
# Trails and event data stores both carry AdvancedEventSelectors: a list of
# selectors, each holding a list of field selectors, each holding one operator
# key whose value is a list of condition values. The engine's Rego has no walk
# builtin and a comprehension may hold only one `some ... in`, so every level
# goes through its own helper.

_pf_ctlib_props(name) := p if {
	p := input.resources[name].properties
	is_object(p)
}

_pf_ctlib_list(o, k) := v if {
	is_object(o)
	v := object.get(o, k, [])
	is_array(v)
}

# A property that is present in the template, whatever its value resolves to.
# object.get on the preprocessed document is the only reliable absence proof:
# resolve() is undefined both for a missing key and for an unresolvable value.
_pf_ctlib_has(name, k) if {
	object.get(_pf_ctlib_props(name), k, "__pf_absent") != "__pf_absent"
}

# A user-written literal. Intrinsics reach Rego as marker objects, so anything
# that is still a string here was written out in the template.
_pf_ctlib_str(name, k) := v if {
	v := object.get(_pf_ctlib_props(name), k, null)
	is_string(v)
}

# ---- basic event selectors -------------------------------------------------

_pf_ctlib_event_selectors(name) := v if v := _pf_ctlib_list(_pf_ctlib_props(name), "EventSelectors")

_pf_ctlib_data_resources(es) := v if v := _pf_ctlib_list(es, "DataResources")

_pf_ctlib_data_resource_values(dr) := v if v := _pf_ctlib_list(dr, "Values")

_pf_ctlib_dr_count(es) := sum([n |
	some dr in _pf_ctlib_data_resources(es)
	n := count(_pf_ctlib_data_resource_values(dr))
])

# Total DataResources.Values across every basic event selector. CloudTrail
# counts the sum ("for all your selectors"), not each array on its own.
_pf_ctlib_data_resource_value_total(name) := sum([n |
	some es in _pf_ctlib_event_selectors(name)
	n := _pf_ctlib_dr_count(es)
])

_pf_ctlib_insight_selectors(name) := v if v := _pf_ctlib_list(_pf_ctlib_props(name), "InsightSelectors")

# ---- advanced event selectors ----------------------------------------------

_pf_ctlib_aes(name) := v if v := _pf_ctlib_list(_pf_ctlib_props(name), "AdvancedEventSelectors")

_pf_ctlib_field_selectors(s) := v if v := _pf_ctlib_list(s, "FieldSelectors")

_pf_ctlib_fields_named(s, field) := {fs |
	some fs in _pf_ctlib_field_selectors(s)
	object.get(fs, "Field", null) == field
}

_pf_ctlib_ops := {"Equals", "NotEquals", "StartsWith", "NotStartsWith", "EndsWith", "NotEndsWith"}

_pf_ctlib_operators(fs) := {op |
	some op in _pf_ctlib_ops
	is_array(object.get(fs, op, null))
}

_pf_ctlib_operator_values(fs, op) := v if v := _pf_ctlib_list(fs, op)

_pf_ctlib_category_is(s, want) if {
	some fs in _pf_ctlib_fields_named(s, "eventCategory")
	some v in _pf_ctlib_operator_values(fs, "Equals")
	v == want
}

_pf_ctlib_logs_management(name) if {
	some s in _pf_ctlib_aes(name)
	_pf_ctlib_category_is(s, "Management")
}

_pf_ctlib_logs_management(name) if {
	some es in _pf_ctlib_event_selectors(name)
	object.get(es, "IncludeManagementEvents", true) == true
}

_pf_ctlib_fs_condition_count(fs) := sum([n |
	some op in _pf_ctlib_ops
	n := count(_pf_ctlib_operator_values(fs, op))
])

_pf_ctlib_sel_condition_count(s) := sum([n |
	some fs in _pf_ctlib_field_selectors(s)
	n := _pf_ctlib_fs_condition_count(fs)
])

# Total condition values across every advanced event selector: the quota
# CloudTrail applies is per trail, not per selector.
_pf_ctlib_aes_condition_total(name) := sum([n |
	some s in _pf_ctlib_aes(name)
	n := _pf_ctlib_sel_condition_count(s)
])

# ---- event data stores -----------------------------------------------------

_pf_ctlib_context_key_selectors(name) := v if v := _pf_ctlib_list(_pf_ctlib_props(name), "ContextKeySelectors")

# ---- ARNs ------------------------------------------------------------------

_pf_ctlib_arn_part(v, i) := p if {
	is_string(v)
	startswith(v, "arn:")
	parts := split(v, ":")
	count(parts) > 5
	p := parts[i]
	p != ""
}

_pf_ctlib_arn_of(v, service) if _pf_ctlib_arn_part(v, 2) == service

# The ARN's own Region, but only when it differs from the deployment Region.
_pf_ctlib_region_mismatch(v) := r if {
	r := _pf_ctlib_arn_part(v, 3)
	region := data.cdk_preflight.deploy_region
	is_string(region)
	r != region
}

# A multi-Region KMS key is usable from any Region; its key id starts with mrk-.
_pf_ctlib_multi_region_key(v) if {
	is_string(v)
	contains(v, ":key/mrk-")
}

# ---- bucket policies -------------------------------------------------------

_pf_ctlib_policy_statements(p) := v if v := _pf_ctlib_list(object.get(_pf_ctlib_props(p), "PolicyDocument", null), "Statement")

# An IAM policy element that CloudFormation lets you write as a string or as a
# list of strings ("Action", "Principal.Service").
_pf_ctlib_str_in(o, k, want) if want in _pf_ctlib_list(o, k)

_pf_ctlib_str_in(o, k, want) if object.get(o, k, null) == want

_pf_ctlib_ct_principal(st) if {
	pr := object.get(st, "Principal", null)
	is_object(pr)
	_pf_ctlib_str_in(pr, "Service", "cloudtrail.amazonaws.com")
}

_pf_ctlib_policy_allows_ct(p) if {
	some st in _pf_ctlib_policy_statements(p)
	object.get(st, "Effect", null) == "Allow"
	_pf_ctlib_ct_principal(st)
	_pf_ctlib_str_in(st, "Action", "s3:PutObject")
}

# Bucket policies in the template that let CloudTrail write to the bucket.
_pf_ctlib_ct_write_policies(bucket) := {p |
	some p in resources_of_type("AWS::S3::BucketPolicy")
	resolve(p, "Properties.Bucket") == bucket
	_pf_ctlib_policy_allows_ct(p)
}
