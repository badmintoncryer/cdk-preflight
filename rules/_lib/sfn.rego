package cdk_preflight

import rego.v1

# Shared helpers for the Step Functions rules (rules/stepfunctions/pf-sfn-*).
# Loaded ahead of every rule (BUNDLED_LIBS); never emits diagnostics.
#
# A definition arrives either as DefinitionString (JSON text — Fn::Join /
# Fn::Sub over pseudo parameters resolve() flattens; a reference to another
# resource does not resolve and the ASL rules skip the machine) or as the raw
# Definition object of an L1 resource (intrinsics inside are marker objects,
# never strings, so is_string guards mute them).

_pf_sfnlib_asl(name) := asl if {
	def := resolve(name, "Properties.DefinitionString")
	is_string(def)
	asl := json.unmarshal(def)
	is_object(asl)
}

_pf_sfnlib_asl(name) := asl if {
	props := input.resources[name].properties
	is_object(props)
	object.get(props, "DefinitionString", "__pf_absent") == "__pf_absent"
	asl := object.get(props, "Definition", null)
	is_object(asl)
}

# Property path prefix for diagnostics.
_pf_sfnlib_prop(name) := "Properties.DefinitionString" if {
	object.get(input.resources[name].properties, "DefinitionString", "__pf_absent") != "__pf_absent"
}

_pf_sfnlib_prop(name) := "Properties.Definition" if {
	object.get(input.resources[name].properties, "DefinitionString", "__pf_absent") == "__pf_absent"
}

# Child workflows directly inside a States block: [path, states, startAt] for
# every Parallel branch and Map ItemProcessor / Iterator.
_pf_sfnlib_kids(path, states) := kids if {
	branches := {[cp, cs, sa] |
		some sname, st in states
		is_object(st)
		arr := object.get(st, "Branches", [])
		is_array(arr)
		some i, b in arr
		is_object(b)
		cs := object.get(b, "States", null)
		is_object(cs)
		sa := object.get(b, "StartAt", null)
		cp := sprintf("%s.%s.Branches[%d].States", [path, sname, i])
	}
	procs := {[cp, cs, sa] |
		some sname, st in states
		is_object(st)
		some key in ["ItemProcessor", "Iterator"]
		proc := object.get(st, key, null)
		is_object(proc)
		cs := object.get(proc, "States", null)
		is_object(cs)
		sa := object.get(proc, "StartAt", null)
		cp := sprintf("%s.%s.%s.States", [path, sname, key])
	}
	kids := branches | procs
}

# Every States block of every state machine: [name, path, states, startAt].
_pf_sfnlib_scope0 contains [name, "States", s, sa] if {
	some name in resources_of_type("AWS::StepFunctions::StateMachine")
	asl := _pf_sfnlib_asl(name)
	s := object.get(asl, "States", null)
	is_object(s)
	sa := object.get(asl, "StartAt", null)
}

_pf_sfnlib_scope1 contains [name, cp, cs, sa] if {
	some [name, p, s, _] in _pf_sfnlib_scope0
	some [cp, cs, sa] in _pf_sfnlib_kids(p, s)
}

_pf_sfnlib_scope2 contains [name, cp, cs, sa] if {
	some [name, p, s, _] in _pf_sfnlib_scope1
	some [cp, cs, sa] in _pf_sfnlib_kids(p, s)
}

_pf_sfnlib_scope3 contains [name, cp, cs, sa] if {
	some [name, p, s, _] in _pf_sfnlib_scope2
	some [cp, cs, sa] in _pf_sfnlib_kids(p, s)
}

# ponytail: Rego cannot recurse and the engine has no walk(), so nesting is
# expanded to depth 3 (Parallel/Map inside Parallel/Map inside Parallel/Map).
# States nested deeper are simply not inspected; add a scope4 line to extend.
_pf_sfnlib_scopes := ((_pf_sfnlib_scope0 | _pf_sfnlib_scope1) | _pf_sfnlib_scope2) | _pf_sfnlib_scope3

# Every state: [name, scope path, scope states, state name, state object].
_pf_sfnlib_states contains [name, p, s, sname, st] if {
	some [name, p, s, _] in _pf_sfnlib_scopes
	some sname, st in s
	is_object(st)
}

_pf_sfnlib_path(name, p, sname) := sprintf("%s.%s.%s", [_pf_sfnlib_prop(name), p, sname])

_pf_sfnlib_type(name) := t if {
	t := resolve(name, "Properties.StateMachineType")
	is_string(t)
}

_pf_sfnlib_type(name) := "STANDARD" if {
	not resolve(name, "Properties.StateMachineType")
}

# Effective query language of a state: state-level, then top-level, then JSONPath.
_pf_sfnlib_ql(name, st) := q if {
	q := object.get(st, "QueryLanguage", null)
	is_string(q)
}

_pf_sfnlib_ql(name, st) := q if {
	not is_string(object.get(st, "QueryLanguage", null))
	q := object.get(_pf_sfnlib_asl(name), "QueryLanguage", null)
	is_string(q)
}

_pf_sfnlib_ql(name, st) := "JSONPath" if {
	not is_string(object.get(st, "QueryLanguage", null))
	not is_string(object.get(_pf_sfnlib_asl(name), "QueryLanguage", null))
}

# Presence test that treats intrinsic marker objects as present.
_pf_sfnlib_has(obj, key) if {
	object.get(obj, key, "__pf_absent") != "__pf_absent"
}

# Choice rules of a Choice state: [name, path, states, state name, index, rule].
_pf_sfnlib_choice contains [name, p, s, sname, i, c] if {
	some [name, p, s, sname, st] in _pf_sfnlib_states
	object.get(st, "Type", null) == "Choice"
	arr := object.get(st, "Choices", null)
	is_array(arr)
	some i, c in arr
	is_object(c)
}

# Optimized / SDK integration Task states: [name, path, states, state name,
# state, service, api] for Resource = arn:<partition>:states:::<service>:<api>.
_pf_sfnlib_integration contains [name, p, s, sname, st, svc, api] if {
	some [name, p, s, sname, st] in _pf_sfnlib_states
	object.get(st, "Type", null) == "Task"
	res := object.get(st, "Resource", null)
	is_string(res)
	parts := split(res, ":")
	count(parts) >= 7
	parts[2] == "states"
	parts[3] == ""
	parts[4] == ""
	svc := parts[5]
	api := concat(":", array.slice(parts, 6, count(parts)))
}
