package cdk_preflight

import rego.v1

_pf_elblacm_fix := "Carry only the *Config that belongs to Action.Type"

_pf_elblacm_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateListener.html"

_pf_elblacm_lists := [
	["AWS::ElasticLoadBalancingV2::Listener", "DefaultActions"],
	["AWS::ElasticLoadBalancingV2::ListenerRule", "Actions"],
]

violation contains make_diag_full("pf-elbv2-listener-action-config-type-match", "ERROR", name,
	sprintf("Properties.%s.%d.%s", [prop, a.index, cfg]),
	sprintf("The action is Type '%s' but carries %s; the service reads only the config that belongs to the type", [t, cfg]),
	_pf_elblacm_fix, _pf_elblacm_url) if {
	some entry in _pf_elblacm_lists
	some name in resources_of_type(entry[0])
	prop := entry[1]
	some a in _pf_elb_actions(name, prop)
	some cfg, want in _pf_elb_action_config
	_pf_elb_ohas(a.value, cfg)
	t := object.get(a.value, "Type", "")
	t != want
}
