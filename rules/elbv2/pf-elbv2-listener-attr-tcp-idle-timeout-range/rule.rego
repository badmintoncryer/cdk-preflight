package cdk_preflight

import rego.v1

_pf_elblati_fix := "Set tcp.idle_timeout.seconds between 60 and 6000"

_pf_elblati_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_ListenerAttribute.html"

violation contains make_diag_full("pf-elbv2-listener-attr-tcp-idle-timeout-range", "ERROR", name,
	sprintf("Properties.ListenerAttributes.%d.Value", [p.index]),
	sprintf("'tcp.idle_timeout.seconds' is %v, outside the accepted range 60-6000", [n]),
	_pf_elblati_fix, _pf_elblati_url) if {
	some name in _pf_elb_listeners
	some p in _pf_elb_pairs(name, "ListenerAttributes")
	p.key == "tcp.idle_timeout.seconds"
	n := _pf_elb_num(p.value)
	_pf_elb_outside(n, 60, 6000)
}
