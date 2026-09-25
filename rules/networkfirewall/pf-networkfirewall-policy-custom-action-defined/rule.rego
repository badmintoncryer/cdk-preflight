package cdk_preflight

import rego.v1

# "After you define a named custom action, you can use it by name in the same
# context as where you defined it" - and nothing below the service reads the
# names, because both lists are plain arrays of strings.
# Undefined - not empty - as soon as the custom actions cannot all be read:
# a set that silently loses an Fn::If element or a Ref'd ActionName would make
# every name in the default lists look undefined.
_pf_nfwpcad_defined(name) := lits if {
	cas := object.get(_pf_nfwlib_fp(name), "StatelessCustomActions", [])
	_pf_countable_items(cas)
	names := [n | some ca in cas; n := object.get(ca, "ActionName", null)]
	lits := {n | some n in names; is_string(n)}
	count(lits) == count(names)
}

violation contains make_diag_full("pf-networkfirewall-policy-custom-action-defined", "ERROR", name,
	sprintf("Properties.FirewallPolicy.%s", [key]),
	sprintf("%s names the custom action '%s', which no StatelessCustomActions entry defines; CreateFirewallPolicy answers \"%s is invalid, parameter: [%s], context: %s\"", [key, a, key, a, key]),
	"Define the custom action in StatelessCustomActions, or name a standard action",
	"https://docs.aws.amazon.com/network-firewall/latest/developerguide/rule-action.html") if {
	some name in resources_of_type("AWS::NetworkFirewall::FirewallPolicy")
	some key in ["StatelessDefaultActions", "StatelessFragmentDefaultActions"]
	acts := object.get(_pf_nfwlib_fp(name), key, null)
	_pf_countable_items(acts)
	# bound before the negation: an unreadable StatelessCustomActions must take
	# the whole body down, not read as "nothing is defined"
	defined := _pf_nfwpcad_defined(name)
	some a in acts
	is_string(a)
	not startswith(a, "aws:")
	not a in defined
}
