package cdk_preflight

import rego.v1

# Shared helpers for the AWS::OpenSearchService::Domain rules. Every constraint
# on this resource hangs off one of the nested option blocks (ClusterConfig /
# EBSOptions / DomainEndpointOptions / CognitoOptions / LogPublishingOptions),
# so the accessors, the absence proof and the ARN split live here once.
# Loaded ahead of every rule (BUNDLED_LIBS); never emits diagnostics.
#
# No threshold constants live here on purpose: test/structure.test.ts reads only
# rule.rego, so a boundary value hidden in this file would skip the check.

_pf_os_domains := resources_of_type("AWS::OpenSearchService::Domain")

# resolve() of a nested option: _pf_os_opt(name, "ClusterConfig", "InstanceCount").
# Undefined for an absent key and for an unresolvable value (Ref to a
# no-default parameter), which is what mutes these rules on tokens.
_pf_os_opt(name, block, key) := resolve(name, sprintf("Properties.%s.%s", [block, key]))

_pf_os_opt3(name, block, sub, key) := resolve(name, sprintf("Properties.%s.%s.%s", [block, sub, key]))

# A flag is "on" only when it is literally true; absent or tokenized is not.
# Write `not _pf_os_on(...)` rather than `resolve(...) != true`, which is
# undefined - and so never fires - exactly when the property is missing.
_pf_os_on(name, block, key) if _pf_os_opt(name, block, key) == true

_pf_os_on3(name, block, sub, key) if _pf_os_opt3(name, block, sub, key) == true

# to_number is undefined for tokens and marker objects, so this doubles as the guard.
_pf_os_num(v) := n if n := to_number(v)

# Absence proof. resolve() is undefined for both "missing" and "present but
# unresolvable", so the only reliable answer comes from the preprocessed
# document (AGENTS.md "Proving a property absent"). is_object fails closed.
_pf_os_obj(v) := o if {
	is_object(v)
	o := v
}

_pf_os_props(name) := p if {
	p := input.resources[name].properties
	is_object(p)
}

_pf_os_at(name, key) := object.get(_pf_os_props(name), key, "__pf_absent")

_pf_os_at2(name, block, key) := object.get(_pf_os_obj(_pf_os_at(name, block)), key, "__pf_absent")

_pf_os_has(name, key) if _pf_os_at(name, key) != "__pf_absent"

_pf_os_missing(name, block, key) if _pf_os_at2(name, block, key) == "__pf_absent"

# Presence one level down (ClusterConfig.WarmCount), for the "X is set but its
# Enabled flag is not" rules. Not `not _pf_os_missing(...)`: that reads true when
# the parent block is absent too, because _pf_os_missing goes undefined there and
# `not undefined` is true - which would fire on a domain carrying neither.
_pf_os_has2(name, block, key) if {
	b := _pf_os_at(name, block)
	is_object(b)
	object.get(b, key, "__pf_absent") != "__pf_absent"
}

# Presence three levels down (AdvancedSecurityOptions.MasterUserOptions.MasterUserName).
# object.get's default stands in for a missing middle block, so an absent parent
# reads as "the key is absent" instead of going undefined.
_pf_os_has3(name, block, sub, key) if {
	b := _pf_os_at(name, block)
	is_object(b)
	s := object.get(b, sub, {})
	is_object(s)
	object.get(s, key, "__pf_absent") != "__pf_absent"
}

# "Elasticsearch_6.5" -> 605, "Elasticsearch_7.10" -> 710. Undefined unless the
# string carries the engine asked for, so an OpenSearch version never answers an
# Elasticsearch question. major*100+minor rather than to_number("6.5"): read as a
# decimal, 2.9 would outrank 2.11.
_pf_os_engine_num(v, engine) := n if {
	is_string(v)
	startswith(v, sprintf("%v_", [engine]))
	parts := split(substring(v, count(engine) + 1, -1), ".")
	count(parts) == 2
	n := (to_number(parts[0]) * 100) + to_number(parts[1])
}

# ARN pieces. Intrinsics reach Rego as marker objects, so is_string() already
# excludes Ref/GetAtt wiring; the "arn:" prefix excludes a resolved logical id.
_pf_os_arn_part(arn, i) := p if {
	is_string(arn)
	startswith(arn, "arn:")
	parts := split(arn, ":")
	count(parts) >= 6
	p := parts[i]
	p != ""
}

_pf_os_arn_region(arn) := _pf_os_arn_part(arn, 3)

_pf_os_arn_account(arn) := _pf_os_arn_part(arn, 4)

# "i3.large.search" -> "i3". Undefined for tokens and for anything undotted.
_pf_os_family(t) := f if {
	is_string(t)
	parts := split(t, ".")
	count(parts) >= 2
	f := parts[0]
}

# Instance families whose storage is instance-backed only: describe-instance-type-limits
# answers StorageTypes ["instance"] with no ebs entry (us-east-1 / OpenSearch_2.19,
# 2026-09-24). A denylist on purpose - a family AWS adds later is a miss, never a
# false positive. i2 is in neither this set nor the EBS-only one (it supports both).
_pf_os_instance_store_families := {"i3", "i4g", "i4i", "i7i", "i8g", "i8ge", "im4gn", "r6gd", "r7gd", "r8gd", "oi2"}

# A Cognito pool id carries its Region in front of a separator:
# UserPoolId "us-east-1_ab12cd", IdentityPoolId "us-east-1:<uuid>". Undefined
# unless the prefix really looks like a Region, so a Ref (which resolves to a
# logical id) and a token are both skipped.
_pf_os_region_prefix(v, sep) := r if {
	is_string(v)
	parts := split(v, sep)
	count(parts) == 2
	r := parts[0]
	regex.match(`^[a-z]{2}(-[a-z]+)+-[0-9]$`, r)
}
