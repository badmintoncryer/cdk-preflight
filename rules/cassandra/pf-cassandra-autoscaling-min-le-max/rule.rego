package cdk_preflight

import rego.v1

_pf_cassmlm_settings contains [name, sprintf("Properties.AutoScalingSpecifications.%s", [k]), s] if {
	some name in resources_of_type("AWS::Cassandra::Table")
	spec := object.get(input.resources[name].properties, "AutoScalingSpecifications", null)
	is_object(spec)
	some k in ["WriteCapacityAutoScaling", "ReadCapacityAutoScaling"]
	s := object.get(spec, k, null)
	is_object(s)
}

violation contains make_diag_full("pf-cassandra-autoscaling-min-le-max", "ERROR", name, p,
	sprintf("MinimumUnits %v is greater than MaximumUnits %v; Keyspaces answers \"maximum_units can not be less than minimum_units\"", [mn, mx]),
	"Make MaximumUnits at least MinimumUnits",
	"https://docs.aws.amazon.com/keyspaces/latest/devguide/autoscaling.html") if {
	some [name, p, s] in _pf_cassmlm_settings
	mn := object.get(s, "MinimumUnits", null)
	mx := object.get(s, "MaximumUnits", null)
	is_number(mn)
	is_number(mx)
	mn > mx
}
