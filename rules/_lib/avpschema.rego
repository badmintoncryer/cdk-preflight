package cdk_preflight

import rego.v1

# Shared helpers for the Amazon Verified Permissions Cedar *schema* rules
# (rules/verifiedpermissions/pf-avp-schema-*). Loaded ahead of every rule
# (BUNDLED_LIBS); never emits diagnostics.
#
# PolicyStore.Schema.CedarJson is a JSON *string* carrying a Cedar schema, and
# Verified Permissions validates its structure whatever ValidationSettings.Mode
# says (probe 2026-09-25: a Mode=OFF store still answers "missing field
# `actions`"), so every rule built on these helpers reads one PolicyStore and
# needs no cross-resource walk.
#
# The Fn::If / token hazard (AGENTS.md #258 / #272) is handled once, in
# _pf_avpsch_stores: resolve() either collapses the intrinsic to a literal
# string or is undefined, and a Ref / Fn::GetAtt that resolves to a logical id
# and a `{{resolve:` dynamic reference are dropped there. Everything past that
# point is a read of an already-parsed object, so no helper can produce two
# outputs for one input ("functions must not produce multiple outputs", which
# would silence the whole pack).

# [logical id, CedarJson text] for every store that spells its schema out.
_pf_avpsch_stores contains [name, s] if {
	some name in resources_of_type("AWS::VerifiedPermissions::PolicyStore")
	s := resolve(name, "Properties.Schema.CedarJson")
	is_string(s)
	not input.resources[s]
	not startswith(s, "{{resolve:")
}

# [logical id, schema] once the text parses to a JSON object. Anything else is
# pf-avp-schema-valid-json-object's business and silences the rest.
_pf_avpsch_parsed contains [name, schema] if {
	some [name, s] in _pf_avpsch_stores
	schema := json.unmarshal(s)
	is_object(schema)
}

# [logical id, namespace name, namespace body].
_pf_avpsch_ns contains [name, nsname, def] if {
	some [name, schema] in _pf_avpsch_parsed
	some nsname, def in schema
	is_object(def)
}

# [logical id, namespace, entity type name, declaration].
_pf_avpsch_ets contains [name, nsname, t, d] if {
	some [name, nsname, def] in _pf_avpsch_ns
	ets := object.get(def, "entityTypes", {})
	is_object(ets)
	some t, d in ets
}

# [logical id, namespace, action name, declaration].
_pf_avpsch_acts contains [name, nsname, a, d] if {
	some [name, nsname, def] in _pf_avpsch_ns
	acts := object.get(def, "actions", {})
	is_object(acts)
	some a, d in acts
}

# [logical id, namespace, common type name, declaration].
_pf_avpsch_cts contains [name, nsname, c, d] if {
	some [name, nsname, def] in _pf_avpsch_ns
	cts := object.get(def, "commonTypes", {})
	is_object(cts)
	some c, d in cts
}

# Entity type references that resolve, as [logical id, namespace doing the
# referring, text]. Unqualified names resolve inside their own namespace;
# a qualified name resolves from anywhere in the same schema. (The empty
# namespace, where Cedar would also accept an unqualified name from another
# namespace, is rejected outright by Verified Permissions - probe-out-4.)
_pf_avpsch_etnames contains [name, nsname, t] if {
	some [name, nsname, t, _] in _pf_avpsch_ets
}

_pf_avpsch_etnames contains [name, user, sprintf("%v::%v", [owner, t])] if {
	some [name, owner, t, _] in _pf_avpsch_ets
	some [n2, user, _] in _pf_avpsch_ns
	n2 == name
}

# Common type references that resolve, same two shapes.
_pf_avpsch_ctnames contains [name, nsname, c] if {
	some [name, nsname, c, _] in _pf_avpsch_cts
}

_pf_avpsch_ctnames contains [name, user, sprintf("%v::%v", [owner, c])] if {
	some [name, owner, c, _] in _pf_avpsch_cts
	some [n2, user, _] in _pf_avpsch_ns
	n2 == name
}

# Action ids declared in a namespace, for the unqualified memberOf form.
_pf_avpsch_actids contains [name, nsname, a] if {
	some [name, nsname, a, _] in _pf_avpsch_acts
}

# Cedar's built-in type keywords. Anything else in a `type` position has to
# resolve to a declared common type or entity type.
_pf_avpsch_builtin := {"String", "Long", "Boolean", "Record", "Set", "Entity", "Extension", "EntityOrCommon"}

# ---- type objects: [logical id, namespace, path for the message, object] ----
#
# The roots are the four places a Cedar JSON schema starts a type: an entity
# type's shape and tags, a common type body, and an action's context.

_pf_avpsch_t0 contains [name, nsname, sprintf("entityTypes.%v.shape", [t]), v] if {
	some [name, nsname, t, d] in _pf_avpsch_ets
	v := object.get(d, "shape", null)
	is_object(v)
}

_pf_avpsch_t0 contains [name, nsname, sprintf("entityTypes.%v.tags", [t]), v] if {
	some [name, nsname, t, d] in _pf_avpsch_ets
	v := object.get(d, "tags", null)
	is_object(v)
}

_pf_avpsch_t0 contains [name, nsname, sprintf("commonTypes.%v", [c]), v] if {
	some [name, nsname, c, v] in _pf_avpsch_cts
	is_object(v)
}

_pf_avpsch_t0 contains [name, nsname, sprintf("actions.%v.appliesTo.context", [a]), v] if {
	some [name, nsname, a, d] in _pf_avpsch_acts
	ap := object.get(d, "appliesTo", {})
	is_object(ap)
	v := object.get(ap, "context", null)
	is_object(v)
}

# A type object's own children: a Record's attributes and a Set's element.
_pf_avpsch_kids(t) := kids if {
	a := {[sprintf("attributes.%v", [k]), v] |
		is_object(t.attributes)
		some k, v in t.attributes
		is_object(v)
	}
	e := {["element", t.element] | is_object(t.element)}
	kids := a | e
}

_pf_avpsch_t1 contains [name, nsname, sprintf("%v.%v", [p, q]), c] if {
	some [name, nsname, p, t] in _pf_avpsch_t0
	some [q, c] in _pf_avpsch_kids(t)
}

_pf_avpsch_t2 contains [name, nsname, sprintf("%v.%v", [p, q]), c] if {
	some [name, nsname, p, t] in _pf_avpsch_t1
	some [q, c] in _pf_avpsch_kids(t)
}

_pf_avpsch_t3 contains [name, nsname, sprintf("%v.%v", [p, q]), c] if {
	some [name, nsname, p, t] in _pf_avpsch_t2
	some [q, c] in _pf_avpsch_kids(t)
}

_pf_avpsch_t4 contains [name, nsname, sprintf("%v.%v", [p, q]), c] if {
	some [name, nsname, p, t] in _pf_avpsch_t3
	some [q, c] in _pf_avpsch_kids(t)
}

_pf_avpsch_t5 contains [name, nsname, sprintf("%v.%v", [p, q]), c] if {
	some [name, nsname, p, t] in _pf_avpsch_t4
	some [q, c] in _pf_avpsch_kids(t)
}

# Every type object down to six levels of nesting. ponytail: Rego has no
# recursion and this engine has no walk(), so the tree is unrolled by hand;
# a seventh level of Record-in-Record is not inspected (hand-written Cedar
# schemas rarely pass three).
_pf_avpsch_types := ((_pf_avpsch_t0 | _pf_avpsch_t1) | (_pf_avpsch_t2 | _pf_avpsch_t3)) | (_pf_avpsch_t4 | _pf_avpsch_t5)
