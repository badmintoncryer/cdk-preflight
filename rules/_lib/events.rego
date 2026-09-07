package cdk_preflight

import rego.v1

# Shared helpers for the EventBridge event-pattern rules
# (rules/events/pf-events-pattern-*). Loaded ahead of every rule
# (BUNDLED_LIBS); never emits diagnostics.
#
# An event pattern is a tree of objects whose leaves are arrays. Array
# elements are either scalars (exact match) or *matcher objects* such as
# {"prefix": "a"}. The engine's Rego has no walk builtin and forbids
# recursion, so the tree is unrolled to a fixed depth: three levels of nested
# objects covers {"detail": {"a": {"b": [...]}}}, which is as deep as real
# patterns go. Each comprehension may hold only one `some ... in`, so every
# level goes through its own helper.
#
# "$or" is not a matcher: its array holds whole pattern objects, so those
# elements are collected as nodes rather than as matchers. Getting that wrong
# would report every key inside a valid $or as an unknown operator.

_pf_evlib_obj_values(n) := {v |
	some k, v in n
	is_object(v)
}

_pf_evlib_or_branches(n) := {e |
	some e in object.get(n, "$or", [])
	is_object(e)
}

_pf_evlib_level(n) := union({_pf_evlib_obj_values(n), _pf_evlib_or_branches(n)})

_pf_evlib_l1(p) := _pf_evlib_level(p)

_pf_evlib_l2(p) := union({_pf_evlib_level(n) | some n in _pf_evlib_l1(p)})

_pf_evlib_l3(p) := union({_pf_evlib_level(n) | some n in _pf_evlib_l2(p)})

# Every object node of the pattern, the pattern itself included.
_pf_evlib_nodes(p) := union({{p}, _pf_evlib_l1(p), _pf_evlib_l2(p), _pf_evlib_l3(p)})

_pf_evlib_arrays_of(n) := {v |
	some k, v in n
	is_array(v)
	k != "$or"
}

# Every matcher array in the pattern ($or arrays excluded).
_pf_evlib_arrays(p) := union({_pf_evlib_arrays_of(n) | some n in _pf_evlib_nodes(p)})

_pf_evlib_objs_of(a) := {e |
	some e in a
	is_object(e)
}

# Every matcher object, e.g. {"prefix": "a"} or {"numeric": [">", 0]}.
_pf_evlib_matchers(p) := union({_pf_evlib_objs_of(a) | some a in _pf_evlib_arrays(p)})

# The pattern as a plain object, or undefined when it is absent or carries
# unresolved intrinsics (marker keys start with "__").
_pf_evlib_pattern(name, path) := p if {
	p := resolve(name, path)
	is_object(p)
	every k, _ in p {
		not startswith(k, "__")
	}
}
