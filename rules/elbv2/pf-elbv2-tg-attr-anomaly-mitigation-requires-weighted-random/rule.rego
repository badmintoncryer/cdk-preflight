package cdk_preflight

import rego.v1

_pf_elbgamw_fix := "Set load_balancing.algorithm.type to weighted_random, or turn anomaly mitigation off"

_pf_elbgamw_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_TargetGroupAttribute.html"

violation contains make_diag_full("pf-elbv2-tg-attr-anomaly-mitigation-requires-weighted-random", "ERROR", name,
	sprintf("Properties.TargetGroupAttributes.%d.Value", [p.index]),
	sprintf("load_balancing.algorithm.anomaly_mitigation is 'on' while the algorithm is '%s'; anomaly mitigation is only available with weighted_random", [alg]),
	_pf_elbgamw_fix, _pf_elbgamw_url) if {
	some name in _pf_elb_tgs
	some p in _pf_elb_pairs(name, "TargetGroupAttributes")
	p.key == "load_balancing.algorithm.anomaly_mitigation"
	p.value == "on"
	alg := _pf_elbgamw_alg(name)
	alg != "weighted_random"
}

_pf_elbgamw_alg(name) := a if {
	s := _pf_elb_attrset(name, "TargetGroupAttributes", "load_balancing.algorithm.type")
	count(s) == 1
	some a in s
}

_pf_elbgamw_alg(name) := "round_robin" if {
	count(_pf_elb_attrset(name, "TargetGroupAttributes", "load_balancing.algorithm.type")) == 0
}
