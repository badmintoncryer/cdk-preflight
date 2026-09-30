package cdk_preflight

import rego.v1

_pf_mc_q_pricingplan_enum_url := "https://docs.aws.amazon.com/mediaconvert/latest/apireference/queues.html"

violation contains make_diag_full("pf-mediaconvert-q-pricingplan-enum", "ERROR", rn, "Properties.PricingPlan",
	sprintf("Queue PricingPlan is %s; it must be ON_DEMAND or RESERVED", [v]),
	"Use ON_DEMAND or RESERVED", _pf_mc_q_pricingplan_enum_url) if {
	some rn in resources_of_type("AWS::MediaConvert::Queue")
	p := input.resources[rn].properties
	is_object(p)
	v := p.PricingPlan
	is_string(v)
	not v in {"ON_DEMAND", "RESERVED"}
}
