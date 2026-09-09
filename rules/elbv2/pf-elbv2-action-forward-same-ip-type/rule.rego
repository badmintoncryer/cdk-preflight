package cdk_preflight

import rego.v1

_pf_elbafsi_fix := "Give every target group of this action the same IpAddressType"

_pf_elbafsi_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/network/load-balancer-listeners.html"

violation contains make_diag_full("pf-elbv2-action-forward-same-ip-type", "ERROR", name,
	sprintf("Properties.%s.%d.ForwardConfig.TargetGroups", [a.prop, a.index]),
	sprintf("The forward action spreads over target groups with different IP address types (%s); one action can only forward to target groups that agree on it", [seen]),
	_pf_elbafsi_fix, _pf_elbafsi_url) if {
	some a in _pf_elb_all_actions
	name := a.name
	tgs := _pf_elb_fwd_tgs(a.value)
	vals := {v |
		some tg in tgs
		g := _pf_elb_tuple_tg(tg)
		v := object.get(_pf_elb_props(g), "IpAddressType", "ipv4")
	}
	count(vals) > 1
	seen := concat(", ", sort(vals))
}
