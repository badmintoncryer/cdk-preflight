package cdk_preflight

import rego.v1

_pf_casstvr_settings contains [name, sprintf("Properties.AutoScalingSpecifications.%s", [k]), s] if {
	some name in resources_of_type("AWS::Cassandra::Table")
	spec := object.get(input.resources[name].properties, "AutoScalingSpecifications", null)
	is_object(spec)
	some k in ["WriteCapacityAutoScaling", "ReadCapacityAutoScaling"]
	s := object.get(spec, k, null)
	is_object(s)
}

violation contains make_diag_full("pf-cassandra-autoscaling-target-value-range", "ERROR", name, concat(".", [p, "ScalingPolicy.TargetTrackingScalingPolicyConfiguration.TargetValue"]),
	sprintf("TargetValue is %v; Keyspaces answers \"target_value must be value between 10 to 90\" (the docs say 20 to 90, the service accepts 10)", [v]),
	"Set TargetValue between 10 and 90",
	"https://docs.aws.amazon.com/keyspaces/latest/devguide/autoscaling.html") if {
	some [name, p, s] in _pf_casstvr_settings
	pol := object.get(s, "ScalingPolicy", null)
	is_object(pol)
	tt := object.get(pol, "TargetTrackingScalingPolicyConfiguration", null)
	is_object(tt)
	v := object.get(tt, "TargetValue", null)
	is_number(v)
	_pf_casstvr_out(v)
}

_pf_casstvr_out(v) if v < 10

_pf_casstvr_out(v) if v > 90
