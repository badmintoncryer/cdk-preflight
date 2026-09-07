package cdk_preflight

import rego.v1

# A custom bus may not take the reserved 'default' name, may not contain a
# slash unless it is a partner bus, and a partner bus's Name must equal its
# EventSourceName. Measured 2026-09-07, events:CreateEventBus, us-east-1:
# 'default' gives "Event bus default already exists", 'team/bus' gives
# "Event bus name must not contain '/'", and a mismatched pair gives
# "Event bus name must match event source name".
_pf_evbusname_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-eventbus.html"

_pf_evbusname(name) := n if {
	n := resolve(name, "Properties.Name")
	is_string(n)
}

_pf_evbussource(name) := s if {
	s := resolve(name, "Properties.EventSourceName")
	is_string(s)
}

violation contains make_diag_full("pf-events-bus-name", "ERROR", name,
	"Properties.Name",
	"'default' is the account's built-in bus, so creating it fails with \"Event bus default already exists\"",
	"Give the custom bus its own name",
	_pf_evbusname_url) if {
	some name in resources_of_type("AWS::Events::EventBus")
	_pf_evbusname(name) == "default"
}

violation contains make_diag_full("pf-events-bus-name", "ERROR", name,
	"Properties.Name",
	sprintf("'%s' contains '/', which only a partner bus may do; CreateEventBus fails with \"Event bus name must not contain '/'\"", [n]),
	"Remove the slash, or set EventSourceName for a partner event source",
	_pf_evbusname_url) if {
	some name in resources_of_type("AWS::Events::EventBus")
	n := _pf_evbusname(name)
	contains(n, "/")
	not _pf_evbussource(name)
}

violation contains make_diag_full("pf-events-bus-name", "ERROR", name,
	"Properties.Name",
	sprintf("A partner bus must be named after its event source, but Name is '%s' and EventSourceName is '%s'; CreateEventBus fails with \"Event bus name must match event source name\"", [n, s]),
	"Set Name to the same value as EventSourceName",
	_pf_evbusname_url) if {
	some name in resources_of_type("AWS::Events::EventBus")
	n := _pf_evbusname(name)
	s := _pf_evbussource(name)
	n != s
}
