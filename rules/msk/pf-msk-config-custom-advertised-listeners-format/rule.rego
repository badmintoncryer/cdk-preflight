package cdk_preflight

import rego.v1

# custom.advertised.listeners is per-broker, so Amazon MSK requires the +{broker_id} suffix that
# tells it how to vary the advertised port per broker. CreateConfiguration rejects any other shape
# with "Invalid custom.advertised.listeners format. Expected:
# LISTENER_NAME://host:port+{broker_id} (comma-separated for multiple)."
_pf_mskcal_entries(name) := es if {
	s := resolve(name, "Properties.ServerProperties")
	is_string(s)
	es := [e |
		some ln in split(s, "\n")
		t := trim_space(ln)
		i := indexof(t, "=")
		i > 0
		trim_space(substring(t, 0, i)) == "custom.advertised.listeners"
		some raw in split(substring(t, i + 1, count(t) - i - 1), ",")
		e := trim_space(raw)
		e != ""
	]
}

violation contains make_diag_full("pf-msk-config-custom-advertised-listeners-format", "ERROR", name,
	"Properties.ServerProperties",
	sprintf("custom.advertised.listeners entry '%s' is not of the form LISTENER_NAME://host:port+{broker_id}; the configuration create fails with \"Invalid custom.advertised.listeners format\"", [bad]),
	"Write each listener as LISTENER_NAME://host:port+{broker_id} (comma-separated for several), e.g. CLIENT://b-{broker_id}.example.com:9092+{broker_id}",
	"https://docs.aws.amazon.com/msk/latest/developerguide/msk-configuration-properties.html") if {
	some name in resources_of_type("AWS::MSK::Configuration")
	some bad in _pf_mskcal_entries(name)
	not regex.match(`^[A-Za-z0-9_]+://[^,]+:[0-9]+\+\{broker_id\}$`, bad)
}
