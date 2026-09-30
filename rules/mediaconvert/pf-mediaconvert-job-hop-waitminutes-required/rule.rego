package cdk_preflight

import rego.v1

_pf_mc_job_hop_waitminutes_required_url := "https://docs.aws.amazon.com/mediaconvert/latest/apireference/jobtemplates.html"

violation contains make_diag_full("pf-mediaconvert-job-hop-waitminutes-required", "ERROR", rn, sprintf("Properties.HopDestinations.%d.WaitMinutes", [i]),
	sprintf("HopDestinations[%d] has no WaitMinutes; the service reads it as null and rejects it (wait time must be between 1 and 4320 minutes)", [i]),
	"Set WaitMinutes on the hop destination", _pf_mc_job_hop_waitminutes_required_url) if {
	some rn in resources_of_type("AWS::MediaConvert::JobTemplate")
	p := input.resources[rn].properties
	is_object(p)
	hops := p.HopDestinations
	is_array(hops)
	some i, h in hops
	_pf_mclib_lit(h)
	object.get(h, "WaitMinutes", "__pf_absent") == "__pf_absent"
}
