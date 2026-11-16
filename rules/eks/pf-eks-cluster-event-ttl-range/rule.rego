package cdk_preflight

import rego.v1

# EventTtl is a duration string. Only the plain <n>s / <n>m / <n>h forms are read;
# anything else (Ref, compound durations) stays silent.
_pf_ekettl_minutes(v) := n if {
	is_string(v)
	regex.match(`^[0-9]+m$`, v)
	n := to_number(trim_suffix(v, "m"))
}

_pf_ekettl_minutes(v) := n if {
	is_string(v)
	regex.match(`^[0-9]+h$`, v)
	n := to_number(trim_suffix(v, "h")) * 60
}

_pf_ekettl_minutes(v) := n if {
	is_string(v)
	regex.match(`^[0-9]+s$`, v)
	n := to_number(trim_suffix(v, "s")) / 60
}

_pf_ekettl_out(m) if m < 10

_pf_ekettl_out(m) if m > 60

violation contains make_diag_full("pf-eks-cluster-event-ttl-range", "ERROR", name,
	"Properties.KubeApiServerConfig.EventTtl",
	sprintf("EventTtl %s is outside 10m-60m; CreateCluster fails with \"kubeApiServerConfig.eventTtl value '%s' is below minimum '10m'\" (or above maximum '60m')", [v, v]),
	"Set EventTtl between 10m and 60m",
	"https://docs.aws.amazon.com/eks/latest/userguide/control-plane-parameters.html") if {
	some name in resources_of_type("AWS::EKS::Cluster")
	cfg := _pf_ekslib_get(name, "KubeApiServerConfig")
	v := _pf_ekslib_oget(cfg, "EventTtl")
	_pf_ekettl_out(_pf_ekettl_minutes(v))
}
