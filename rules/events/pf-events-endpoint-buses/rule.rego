package cdk_preflight

import rego.v1

# A global endpoint fronts exactly two same-named buses in two Regions, and
# the failover secondary Route must be the second bus's Region. Measured
# 2026-09-07, events:CreateEndpoint, us-east-1: listing the same bus twice or
# routing to a Region with no bus gives "An event bus must be provided in
# both the primary and secondary regions", and differing bus names give
# "Event bus names must match in the primary and secondary regions". These
# checks run before the health check is looked up, so they surface on their
# own.
_pf_evep_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-endpoint.html"

_pf_evep_arns(name) := [a |
	some b in flatten_list(name, "Properties.EventBuses")
	is_object(b.value)
	a := object.get(b.value, "EventBusArn", null)
	is_string(a)
]

_pf_evep_part(arn, i) := parts[i] if {
	parts := split(arn, ":")
	count(parts) > i
}

_pf_evep_bus_name(arn) := n if {
	parts := split(arn, "/")
	count(parts) > 1
	n := parts[count(parts) - 1]
}

violation contains make_diag_full("pf-events-endpoint-buses", "ERROR", name,
	"Properties.EventBuses",
	sprintf("Both event buses are in '%s'; CreateEndpoint fails with \"An event bus must be provided in both the primary and secondary regions\"", [_pf_evep_part(arns[0], 3)]),
	"Reference one bus in each of the two Regions",
	_pf_evep_url) if {
	some name in resources_of_type("AWS::Events::Endpoint")
	arns := _pf_evep_arns(name)
	count(arns) == 2
	_pf_evep_part(arns[0], 3) == _pf_evep_part(arns[1], 3)
}

violation contains make_diag_full("pf-events-endpoint-buses", "ERROR", name,
	"Properties.EventBuses",
	sprintf("The buses are named '%s' and '%s'; CreateEndpoint fails with \"Event bus names must match in the primary and secondary regions\"", [_pf_evep_bus_name(arns[0]), _pf_evep_bus_name(arns[1])]),
	"Use the same bus name in both Regions",
	_pf_evep_url) if {
	some name in resources_of_type("AWS::Events::Endpoint")
	arns := _pf_evep_arns(name)
	count(arns) == 2
	_pf_evep_bus_name(arns[0]) != _pf_evep_bus_name(arns[1])
}

violation contains make_diag_full("pf-events-endpoint-buses", "ERROR", name,
	"Properties.RoutingConfig.FailoverConfig.Secondary.Route",
	sprintf("The secondary route is '%s' but neither bus lives there; CreateEndpoint fails with \"An event bus must be provided in both the primary and secondary regions\"", [route]),
	"Set Secondary.Route to the Region of the second event bus",
	_pf_evep_url) if {
	some name in resources_of_type("AWS::Events::Endpoint")
	arns := _pf_evep_arns(name)
	count(arns) == 2
	route := resolve(name, "Properties.RoutingConfig.FailoverConfig.Secondary.Route")
	is_string(route)
	regions := {r | some a in arns; r := _pf_evep_part(a, 3)}
	not route in regions
}
