package cdk_preflight

import rego.v1

# Shared helpers for the AWS IoT Core rules (rules/iot/pf-iot-*).
# Loaded ahead of every rule (BUNDLED_LIBS); never emits diagnostics.
#
# Three opaque shapes live in this service and each one needs a different door:
#   - TopicRulePayload.Sql is a *string* DSL — pulled apart with regex/split
#     (_pf_iotlib_sql / _pf_iotlib_topic).
#   - Policy.PolicyDocument is either an object or a *JSON string*
#     (_pf_iotlib_policy_docs); statements come back through the IAM library's
#     _pf_iamlib_stmts, which already handles the object-or-array Statement.
#   - ProvisioningTemplate.TemplateBody is a JSON string too (not used yet —
#     the C-2 slice adds _pf_iotlib_template_body next to _pf_iotlib_policy_docs).

# Raw properties: intrinsics are still marker objects here, so is_string proves
# the user wrote a literal.
_pf_iotlib_props(name) := p if {
	p := object.get(input.resources[name], "properties", {})
	is_object(p)
}

# A literal string property (resolve() hands back a logical id for Ref/GetAtt,
# so a bare is_string is not proof of a literal).
_pf_iotlib_lit(name, path) := s if {
	s := resolve(name, path)
	is_string(s)
	not input.resources[s]
}

_pf_iotlib_has(name, key) if {
	object.get(_pf_iotlib_props(name), key, "__pf_absent") != "__pf_absent"
}

# An object whose key count can be trusted: no intrinsic marker key and no
# value that disappears at deploy time. count() of a marker object returns its
# key count, so every count() over user JSON goes through this first.
_pf_iotlib_plain_obj(v) if {
	is_object(v)
	count([k |
		some k in object.keys(v)
		_pf_iotlib_opaque(k, object.get(v, k, null))
	]) == 0
}

_pf_iotlib_opaque(k, _) if startswith(k, "__")

_pf_iotlib_opaque(_, x) if _pf_ll_conditional(x)

# --- TopicRule -------------------------------------------------------------

_pf_iotlib_sql(name) := _pf_iotlib_lit(name, "Properties.TopicRulePayload.Sql")

# The topic filter between the quotes of FROM '<filter>'. Undefined when the
# statement has no quoted FROM — CreateTopicRule accepts those (a missing FROM
# and a double-quoted topic both deploy), so silence is the right answer.
_pf_iotlib_topic(sql) := tf if {
	m := regex.find_n(`(?i)FROM\s+'[^']*'`, sql, 1)
	count(m) == 1
	tf := split(m[0], "'")[1]
}

# MQTT topic filter rules the broker enforces: '#' is the last level and alone
# in it, '+' is alone in its level. (There is no limit on the number of levels
# — 8 and 14 slashes both deploy.)
_pf_iotlib_topic_bad(tf) if {
	lv := split(tf, "/")
	some i, l in lv
	indexof(l, "#") != -1
	not _pf_iotlib_hash_ok(l, i, count(lv))
}

_pf_iotlib_topic_bad(tf) if {
	lv := split(tf, "/")
	some _, l in lv
	indexof(l, "+") != -1
	l != "+"
}

_pf_iotlib_hash_ok(l, i, n) if {
	l == "#"
	i == n - 1
}

# Every literal element of Actions[] as [resource, index, object]. ErrorAction
# is deliberately absent: the service accepts two keys there and only polices
# the entries of Actions[].
_pf_iotlib_action contains [name, i, a] if {
	some name in resources_of_type("AWS::IoT::TopicRule")
	acts := object.get(_pf_iotlib_props(name), ["TopicRulePayload", "Actions"], null)
	is_array(acts)
	some i, a in acts
	_pf_iotlib_plain_obj(a)
}

# --- Policy ----------------------------------------------------------------

# Policy documents of AWS::IoT::Policy, as [resource, path, document]; the
# property takes an object or a JSON string.
_pf_iotlib_policy_docs contains [name, "Properties.PolicyDocument", d] if {
	some name in resources_of_type("AWS::IoT::Policy")
	d := object.get(_pf_iotlib_props(name), "PolicyDocument", null)
	is_object(d)
	not _pf_iotlib_opaque_doc(d)
}

_pf_iotlib_policy_docs contains [name, "Properties.PolicyDocument", d] if {
	some name in resources_of_type("AWS::IoT::Policy")
	s := _pf_iotlib_lit(name, "Properties.PolicyDocument")
	d := json.unmarshal(s)
	is_object(d)
}

_pf_iotlib_opaque_doc(d) if {
	some k in object.keys(d)
	startswith(k, "__")
}

# --- ProvisioningTemplate ---------------------------------------------------

# The provisioning template's own document, which rides inside a CloudFormation
# string property. Same two doors as PolicyDocument: an object (rare, but the
# L1 takes one) or the JSON string everybody actually writes.
_pf_iotlib_template_body(name) := d if {
	d := object.get(_pf_iotlib_props(name), "TemplateBody", null)
	is_object(d)
	not _pf_iotlib_opaque_doc(d)
}

_pf_iotlib_template_body(name) := d if {
	s := _pf_iotlib_lit(name, "Properties.TemplateBody")
	json.is_valid(s)
	d := json.unmarshal(s)
	is_object(d)
}

# --- ARNs ------------------------------------------------------------------

# The region of a literal ARN for a given service. Undefined for everything
# else - a Ref/GetAtt resolves to a logical id, an unresolvable intrinsic stays
# a marker object - so the three region rules skip whatever they cannot read.
_pf_iotlib_arn_region(arn, service) := r if {
	is_string(arn)
	parts := split(arn, ":")
	count(parts) >= 7
	parts[0] == "arn"
	parts[2] == service
	r := parts[3]
	r != ""
}
