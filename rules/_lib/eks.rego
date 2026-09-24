package cdk_preflight

import rego.v1

# Shared helpers for the EKS rules. Absence is proven against the preprocessed
# document (resolve() cannot tell "absent" from "unresolvable"), and every
# string comparison is limited to user literals so a Ref never fires a rule.
# Loaded ahead of every rule (BUNDLED_LIBS); never emits diagnostics.

_pf_ekslib_props(name) := p if {
	p := input.resources[name].properties
	is_object(p)
}

# Absent-safe object access; undefined when the key is missing.
_pf_ekslib_oget(o, k) := v if {
	is_object(o)
	v := object.get(o, k, "__pf_absent")
	v != "__pf_absent"
}

_pf_ekslib_ohas(o, k) if {
	_pf_ekslib_oget(o, k)
}

_pf_ekslib_get(name, k) := v if {
	v := _pf_ekslib_oget(_pf_ekslib_props(name), k)
}

_pf_ekslib_has(name, k) if {
	_pf_ekslib_get(name, k)
}

# A user-written literal, not a Ref/GetAtt that resolve() turned into a logical id.
_pf_ekslib_lit(v) if {
	is_string(v)
	not input.resources[v]
}

# Kubernetes qualified name: an optional DNS-subdomain prefix before "/" and a
# name segment of at most 63 characters. EKS runs the same validator over node
# group labels and taint keys, and reports the same regex in both messages.
_pf_ekslib_qualified_name(k) if {
	_pf_ekslib_lit(k)
	parts := split(k, "/")
	count(parts) == 1
	_pf_ekslib_name_seg(parts[0])
}

_pf_ekslib_qualified_name(k) if {
	_pf_ekslib_lit(k)
	parts := split(k, "/")
	count(parts) == 2
	_pf_ekslib_dns_subdomain(parts[0])
	_pf_ekslib_name_seg(parts[1])
}

_pf_ekslib_name_seg(s) if {
	count(s) > 0
	count(s) <= 63
	regex.match(`^[A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?$`, s)
}

_pf_ekslib_dns_subdomain(s) if {
	count(s) > 0
	count(s) <= 253
	regex.match(`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`, s)
}

# Prefixes EKS refuses in an access entry's Username and in every KubernetesGroups
# name. Measured one at a time against CreateAccessEntry on 2026-09-25; the service
# echoes the offending prefix back. "sts:" is not among them, so the set is closed.
_pf_ekslib_reserved_prefixes := ["system:", "eks:", "aws:", "amazon:", "iam:"]
