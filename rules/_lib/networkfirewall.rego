package cdk_preflight

import rego.v1

# Shared helpers for the AWS Network Firewall rules (rules/networkfirewall/pf-networkfirewall-*).
# Loaded ahead of every rule (BUNDLED_LIBS); never emits diagnostics.
#
# The opaque shape of this service is RulesSource.RulesString: a Suricata rule
# file that CloudFormation carries as one string and that CreateRuleGroup really
# parses (it answers with the offending rule verbatim). Everything from
# _pf_nfwlib_rule_lines down is a hand-rolled parser for it, because the registry
# schema has no oneOf/anyOf/allOf/dependencies at all and sees a plain string.
#
# Two facts the parser depends on, both measured against CreateRuleGroup
# (DryRun, us-east-1, 2026-09-25):
#   - Backslash line continuation is NOT supported ("Illegal option syntax: \"),
#     so one line is exactly one rule and splitting on "\n" is safe.
#   - Only the rule *header* (the text before the first "(") carries $variables
#     and @ip-set-references. `msg:"costs $USD"` and `pcre:"/\$HOME/"` are both
#     accepted, so scanning the whole line would flag valid rules.

_pf_nfwlib_props(name) := p if {
	p := object.get(input.resources[name], "properties", {})
	is_object(p)
}

# A literal string property (resolve() hands back a logical id for Ref/GetAtt,
# so a bare is_string is not proof of a literal).
_pf_nfwlib_lit(name, path) := s if {
	s := resolve(name, path)
	is_string(s)
	not input.resources[s]
}

# The region of a literal ARN for a given service; undefined for anything else.
_pf_nfwlib_arn_region(arn, service) := r if {
	is_string(arn)
	parts := split(arn, ":")
	count(parts) >= 6
	parts[0] == "arn"
	parts[2] == service
	r := parts[3]
	r != ""
}

# --- Suricata RulesString ---------------------------------------------------

_pf_nfwlib_rules_string(name) := _pf_nfwlib_lit(name, "Properties.RuleGroup.RulesSource.RulesString")

# Rule lines: trimmed, without blanks and without "#" comments. The stateful
# capacity a rule group consumes is the length of this list (measured: a
# 250-rule string reports ConsumedCapacity 250).
_pf_nfwlib_rule_lines(s) := [l |
	some raw in split(s, "\n")
	l := trim(raw, " \t\r")
	l != ""
	not startswith(l, "#")
]

# Every Suricata rule line of every rule group, as [resource, index, line].
_pf_nfwlib_line contains [name, i, l] if {
	some name in resources_of_type("AWS::NetworkFirewall::RuleGroup")
	some i, l in _pf_nfwlib_rule_lines(_pf_nfwlib_rules_string(name))
}

# Every element of RulesSource.StatefulRules[], as [resource, index, rule].
_pf_nfwlib_stateful_rule contains [name, i, r] if {
	some name in resources_of_type("AWS::NetworkFirewall::RuleGroup")
	rs := object.get(_pf_nfwlib_props(name), ["RuleGroup", "RulesSource", "StatefulRules"], null)
	is_array(rs)
	some i, r in rs
	is_object(r)
	not _pf_ll_conditional(r)
}

# Rule messages quote the offending line; keep them readable (a rule can be
# 8,175 characters long).
_pf_nfwlib_snip(l) := substring(l, 0, 72)

# "action proto src sport -> dst dport", the part before the options.
_pf_nfwlib_rule_header(l) := substring(l, 0, i) if {
	i := indexof(l, "(")
	i > 0
}

_pf_nfwlib_rule_header(l) := l if {
	indexof(l, "(") == -1
}

_pf_nfwlib_header_tokens(l) := [t |
	some raw in split(_pf_nfwlib_rule_header(l), " ")
	t := trim(raw, " \t")
	t != ""
]

_pf_nfwlib_rule_action(l) := toks[0] if {
	toks := _pf_nfwlib_header_tokens(l)
	count(toks) >= 2
}

_pf_nfwlib_rule_protocol(l) := toks[1] if {
	toks := _pf_nfwlib_header_tokens(l)
	count(toks) >= 2
}

# The ";"-separated options inside the trailing parentheses. Suricata escapes a
# literal ";" inside a value as "\;", so splitting on ";" only mis-parses input
# the service rejects anyway.
_pf_nfwlib_rule_options(l) := opts if {
	i := indexof(l, "(")
	i > 0
	endswith(l, ")")
	inner := substring(l, i + 1, count(l) - i - 2)
	opts := [o |
		some raw in split(inner, ";")
		o := trim(raw, " \t")
		o != ""
	]
}

_pf_nfwlib_option_name(o) := trim(substring(o, 0, indexof(o, ":")), " \t") if {
	indexof(o, ":") > 0
}

_pf_nfwlib_option_name(o) := o if {
	indexof(o, ":") == -1
}

# Option names of one rule line. The charset guard drops the fragments a value
# containing an unescaped ";" would otherwise leave behind.
_pf_nfwlib_option_names(l) := {n |
	some o in _pf_nfwlib_rule_options(l)
	n := _pf_nfwlib_option_name(o)
	regex.match(`^[a-z0-9_.]+$`, n)
}

_pf_nfwlib_option_values(l, key) := [v |
	some o in _pf_nfwlib_rule_options(l)
	startswith(o, sprintf("%s:", [key]))
	v := trim(trim_prefix(o, sprintf("%s:", [key])), " \t")
]

# --- rule group settings the DSL depends on ---------------------------------

_pf_nfwlib_rule_order(name) := _pf_nfwlib_lit(name, "Properties.RuleGroup.StatefulRuleOptions.RuleOrder")

# The only two variables the service resolves on its own. Measured one by one:
# HTTP_PORTS, HTTPS_PORTS, SSH_PORTS, DNS_SERVERS and 13 more Suricata defaults
# are all rejected with "<NAME> cannot be null or empty", so widening this set
# loses findings rather than causing false ones.
_pf_nfwlib_builtin_vars := {"HOME_NET", "EXTERNAL_NET"}

_pf_nfwlib_map_keys(name, path) := object.keys(v) if {
	v := object.get(_pf_nfwlib_props(name), path, null)
	is_object(v)
}

_pf_nfwlib_map_keys(name, path) := set() if {
	not is_object(object.get(_pf_nfwlib_props(name), path, null))
}

_pf_nfwlib_declared_vars(name) := _pf_nfwlib_map_keys(name, ["RuleGroup", "RuleVariables", "IPSets"]) | _pf_nfwlib_map_keys(name, ["RuleGroup", "RuleVariables", "PortSets"])

_pf_nfwlib_declared_refs(name) := _pf_nfwlib_map_keys(name, ["RuleGroup", "ReferenceSets", "IPSetReferences"])

# $VAR and @ref uses, taken from the header only (see the note at the top).
_pf_nfwlib_header_vars(l) := {v |
	some m in regex.find_n(`\$[A-Za-z_][A-Za-z0-9_]*`, _pf_nfwlib_rule_header(l), -1)
	v := trim_prefix(m, "$")
}

_pf_nfwlib_header_refs(l) := {r |
	some m in regex.find_n(`@[A-Za-z0-9_]+`, _pf_nfwlib_rule_header(l), -1)
	r := trim_prefix(m, "@")
}

# --- TLS inspection configuration -------------------------------------------

_pf_nfwlib_tls_configs(name) := c if {
	c := object.get(_pf_nfwlib_props(name), ["TLSInspectionConfiguration", "ServerCertificateConfigurations"], null)
	is_array(c)
}

_pf_nfwlib_tls_config contains [name, i, cfg] if {
	some name in resources_of_type("AWS::NetworkFirewall::TLSInspectionConfiguration")
	some i, cfg in _pf_nfwlib_tls_configs(name)
	is_object(cfg)
	not _pf_ll_conditional(cfg)
}

_pf_nfwlib_tls_scope contains [name, ci, si, sc] if {
	some [name, ci, cfg] in _pf_nfwlib_tls_config
	scopes := object.get(cfg, "Scopes", null)
	is_array(scopes)
	some si, sc in scopes
	is_object(sc)
	not _pf_ll_conditional(sc)
}

# --- stateless rules and the capacity they consume ---------------------------

# Every element of RulesSource.StatelessRulesAndCustomActions.StatelessRules[],
# as [resource, index, rule].
_pf_nfwlib_stateless_rules contains [name, i, r] if {
	some name in resources_of_type("AWS::NetworkFirewall::RuleGroup")
	rs := object.get(_pf_nfwlib_props(name), ["RuleGroup", "RulesSource", "StatelessRulesAndCustomActions", "StatelessRules"], null)
	is_array(rs)
	some i, r in rs
	is_object(r)
	not _pf_ll_conditional(r)
}

# The capacity a stateless rule group consumes: per rule the product of the
# element counts of Sources, Destinations, SourcePorts, DestinationPorts and
# Protocols (an unset match setting counts as 1), summed over the rules. This is
# a different formula from the stateful one (one unit per rule) and from the
# domain list one (Targets * TargetTypes + TargetTypes + 1).
# Measured against CreateRuleGroup (DryRun, us-east-1, 2026-09-25): one rule with
# three Sources and two Protocols answers "StatelessRules capacity exceeded,
# parameter: [6]". Undefined as soon as one list cannot be counted, so a
# template the count cannot be read out of is left alone.
_pf_nfwlib_stateless_cost(name) := sum(costs) if {
	rules := object.get(_pf_nfwlib_props(name), ["RuleGroup", "RulesSource", "StatelessRulesAndCustomActions", "StatelessRules"], null)
	_pf_countable_items(rules)
	costs := [c |
		some r in rules
		ma := object.get(r, ["RuleDefinition", "MatchAttributes"], {})
		is_object(ma)
		not _pf_ll_conditional(ma)
		dims := [n |
			some key in ["Sources", "Destinations", "SourcePorts", "DestinationPorts", "Protocols"]
			v := object.get(ma, key, [])
			_pf_countable_items(v)
			n := max([1, count(v)])
		]
		count(dims) == 5
		c := (((dims[0] * dims[1]) * dims[2]) * dims[3]) * dims[4]
	]
	count(costs) == count(rules)
}
