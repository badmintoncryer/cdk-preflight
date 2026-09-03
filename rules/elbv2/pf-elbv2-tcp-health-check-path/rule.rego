package cdk_preflight

import rego.v1

_pf_elbtchp_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateTargetGroup.html"

_pf_elbtchp_tcp_hc(name) if resolve(name, "Properties.HealthCheckProtocol") == "TCP"

# HealthCheckProtocol defaults to the target group protocol (benched via e04b).
_pf_elbtchp_tcp_hc(name) if {
	props := input.resources[name].properties
	is_object(props)
	object.get(props, "HealthCheckProtocol", "__pf_absent") == "__pf_absent"
	resolve(name, "Properties.Protocol") == "TCP"
}

violation contains make_diag_full("pf-elbv2-tcp-health-check-path", "ERROR", name,
	"Properties.HealthCheckPath",
	"The effective health check protocol is TCP, which cannot take HealthCheckPath (\"Health check paths are not supported for TCP health checks\")",
	"Remove HealthCheckPath, or use an HTTP/HTTPS health check protocol",
	_pf_elbtchp_url) if {
	some name in resources_of_type("AWS::ElasticLoadBalancingV2::TargetGroup")
	_pf_elbtchp_tcp_hc(name)
	props := input.resources[name].properties
	is_object(props)
	object.get(props, "HealthCheckPath", "__pf_absent") != "__pf_absent"
}
