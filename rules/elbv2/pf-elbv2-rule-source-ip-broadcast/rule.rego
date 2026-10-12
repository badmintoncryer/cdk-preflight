package cdk_preflight

import rego.v1

# The ALB guide names exactly one CIDR that a source-ip condition refuses, and the
# service answers it as an invalid CIDR block although it is well formed (so
# pf-elbv2-rule-source-ip-cidr lets it through). Other special ranges (multicast,
# 240.0.0.0/4, host bits set) are neither documented nor observed, so they are left alone.
_pf_elbrsb_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/rule-condition-types.html#source-ip-conditions"

violation contains make_diag_full("pf-elbv2-rule-source-ip-broadcast", "ERROR", name,
	sprintf("Properties.Conditions.%d", [c.index]),
	sprintf("The specified value '%s' is not a valid CIDR block: an ALB source-ip condition cannot take the limited broadcast address", [v]),
	"For a rule that never matches, use a documentation-only address such as 192.0.2.1/32 (RFC 5737)", _pf_elbrsb_url) if {

	some name in _pf_elb_rules
	some c in _pf_elb_conditions(name)
	object.get(c.value, "Field", "") == "source-ip"
	some v in _pf_elb_cond_values(c.value)
	v == "255.255.255.255/32"
}
