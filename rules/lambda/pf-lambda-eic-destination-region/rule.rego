package cdk_preflight

import rego.v1

_pf_leidr_fix := "Point the destination at a resource in the same region as the function"

_pf_leidr_url := "https://docs.aws.amazon.com/lambda/latest/api/API_OnFailure.html"

violation contains make_diag_full("pf-lambda-eic-destination-region", "ERROR", name,
	sprintf("Properties.DestinationConfig.%v.Destination", [side]),
	sprintf("%v destination region '%v' is not the deploy region '%v'; invocation records are delivered in-region and the config create is rejected", [side, parts[3], region]),
	_pf_leidr_fix, _pf_leidr_url) if {
	region := data.cdk_preflight.deploy_region
	some [name, side, dest] in _pf_lam_eic_dest
	parts := _pf_lam_arn(dest)
	parts[3] != ""
	parts[3] != region
}
