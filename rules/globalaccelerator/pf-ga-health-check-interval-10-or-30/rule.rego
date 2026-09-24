package cdk_preflight

import rego.v1

# The health check interval is a two-value choice, not a range: "The time - 10
# seconds or 30 seconds - between each health check for an endpoint." The schema
# only bounds the property to 10-30, so every value in between is schema-clean.
violation contains make_diag_full("pf-ga-health-check-interval-10-or-30", "ERROR", name,
	"Properties.HealthCheckIntervalSeconds",
	sprintf("The endpoint group asks for a %v second health check interval; Global Accelerator accepts only 10 or 30", [v]),
	"Set HealthCheckIntervalSeconds to 10 or 30, or leave it out to take the default 30",
	"https://docs.aws.amazon.com/global-accelerator/latest/api/API_CreateEndpointGroup.html") if {
	some name in _pf_galib_groups
	v := _pf_galib_int(_pf_galib_get(name, "HealthCheckIntervalSeconds"))
	not v in {10, 30}
}
