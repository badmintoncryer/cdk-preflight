package cdk_preflight

import rego.v1

_pf_elbraor_fix := "Keep one forward, redirect or fixed-response action (authentication actions go before it)"

_pf_elbraor_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_Action.html"

violation contains make_diag_full("pf-elbv2-rule-actions-exactly-one-routing", "ERROR", name,
	"Properties.Actions",
	sprintf("The rule holds %d routing actions (forward, redirect, fixed-response); a rule ends on exactly one of them", [n]),
	_pf_elbraor_fix, _pf_elbraor_url) if {
	some name in _pf_elb_rules
	n := count([a |
		some a in _pf_elb_actions(name, "Actions")
		object.get(a.value, "Type", "") in _pf_elb_routing_actions
	])
	n != 1
}
