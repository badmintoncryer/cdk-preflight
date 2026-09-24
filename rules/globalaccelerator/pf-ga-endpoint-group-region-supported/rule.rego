package cdk_preflight

import rego.v1

# EndpointGroupRegion is only length-capped by the schema (255 characters), so a
# mistyped Region code reaches the service and CreateEndpointGroup rejects it.
violation contains make_diag_full("pf-ga-endpoint-group-region-supported", "ERROR", name,
	"Properties.EndpointGroupRegion",
	sprintf("Region code %v is not an AWS Region, so the endpoint group cannot be created there", [r]),
	"Set EndpointGroupRegion to the Region code the endpoints live in, such as us-west-2",
	"https://docs.aws.amazon.com/global-accelerator/latest/api/API_CreateEndpointGroup.html") if {
	some name in _pf_galib_groups
	r := _pf_galib_str(name, "EndpointGroupRegion")
	_pf_galib_lit(r)
	not r in _pf_galib_regions
}
