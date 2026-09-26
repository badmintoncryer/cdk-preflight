package cdk_preflight

import rego.v1

# ---- literal string properties ---------------------------------------------

# A property value, but only when it resolved to a literal string. A Fn::Sub /
# Fn::Join that still references a resource is undefined under resolve(), and a
# Ref comes back as a marker object, so every rule built on this stays silent on
# the templates CDK ordinarily emits for a composed YAML/JSON body (#258 family).
_pf_aps_str(name, path) := s if {
	s := resolve(name, path)
	is_string(s)
}

# ---- block-style YAML ------------------------------------------------------

# The engine has no yaml.unmarshal (evaluating it is a hard error, not
# undefined), so the Prometheus rules file in RuleGroupsNamespace.Data and the
# Alertmanager config in Workspace.AlertManagerDefinition are read line by line.
#
# Only a plain `key: value` line, optionally opened by a `- `, is kept: flow
# style, block scalars, comments and continuation lines produce no line at all,
# so a rule built on this reader errs toward silence rather than a false
# positive. Values are unquoted so `name: ""` and `name:` read the same.
_pf_aps_yaml_lines(body) := [line |
	some n, raw in split(body, "\n")
	m := regex.find_all_string_submatch_n(`^( *)(- )?([A-Za-z_][A-Za-z0-9_.]*):($| .*$)`, raw, 1)[0]
	line := {
		"n": n,
		"indent": count(m[1]) + count(m[2]),
		"dash": m[2] != "",
		"key": m[3],
		"value": _pf_aps_unquote(trim_space(m[4])),
	}
]

_pf_aps_unquote(v) := regex.replace(v, `^["']|["']$`, "")

# A line that closes the item opened by `start`: either it left the enclosing
# block, or it opens the next sibling item. A deeper nested block (labels:,
# annotations:) is neither, so it stays inside the item.
_pf_aps_yaml_ends(start, line) if line.indent < start.indent

_pf_aps_yaml_ends(start, line) if {
	line.indent == start.indent
	line.dash
}

# The line number where the item opened by `start` ends. The sentinel keeps the
# minimum defined for an item that runs to the end of the body.
_pf_aps_yaml_item_end(lines, start) := min({e |
	some line in lines
	line.n > start.n
	_pf_aps_yaml_ends(start, line)
	e := line.n
} | {1000000})

# The [key, value] pairs of the item opened by `start`. A set of pairs, not an
# object: an object comprehension over a duplicated YAML key is a hard
# evaluation error that would silence every rule in the pack.
_pf_aps_yaml_item(lines, start) := {[line.key, line.value] |
	some line in lines
	line.n >= start.n
	line.indent == start.indent
	line.n < _pf_aps_yaml_item_end(lines, start)
}

_pf_aps_keys(pairs) := {k | some p in pairs; k := p[0]}

_pf_aps_values(pairs, key) := {v |
	some p in pairs
	p[0] == key
	v := p[1]
}

# ---- ResourcePolicy.PolicyDocument -----------------------------------------

# The parsed PolicyDocument. json.unmarshal is available (yaml.unmarshal is
# not), and every level is type-guarded because indexing or iterating a scalar
# read out of user JSON is a hard evaluation error, not undefined.
_pf_aps_policy(name) := parsed if {
	doc := _pf_aps_str(name, "Properties.PolicyDocument")
	json.is_valid(doc)
	parsed := json.unmarshal(doc)
	is_object(parsed)
}

_pf_aps_policy_statements(name) := [s |
	list := object.get(_pf_aps_policy(name), "Statement", [])
	is_array(list)
	some s in list
	is_object(s)
]

# A statement field that IAM allows as either a string or a list of strings, as
# the set of strings in it. Any other shape yields nothing.
_pf_aps_policy_strings(statement, key) := {v |
	raw := object.get(statement, key, null)
	some v in ({x | is_string(raw); x := raw} | {x | is_array(raw); some x in raw})
	is_string(v)
}
