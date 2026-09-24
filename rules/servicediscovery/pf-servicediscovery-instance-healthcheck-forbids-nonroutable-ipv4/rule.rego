package cdk_preflight

import rego.v1

# Route 53 health checks only reach publicly routable addresses, so a health-checked
# service rejects the address at registration time. Only the ranges below are listed:
# RFC 1918 private space, the three RFC 5737 documentation blocks, loopback and
# link-local. 10.0.0.0/8 and 192.0.2.0/24 are the two that were observed being
# refused; the rest are the same "cannot be reached from the internet" address space.
# Ranges whose refusal was neither observed nor obvious (CGNAT 100.64/10, RFC 2544
# 198.18/15, multicast and class E) are deliberately left out rather than guessed at.
# Written as patterns rather than octet comparisons: this is address space, not a
# tunable threshold.
_pf_sdnr_reserved(ip) if regex.match(`^10\.`, ip)
_pf_sdnr_reserved(ip) if regex.match(`^127\.`, ip)
_pf_sdnr_reserved(ip) if regex.match(`^169\.254\.`, ip)
_pf_sdnr_reserved(ip) if regex.match(`^172\.(1[6-9]|2[0-9]|3[01])\.`, ip)
_pf_sdnr_reserved(ip) if regex.match(`^192\.168\.`, ip)
_pf_sdnr_reserved(ip) if regex.match(`^192\.0\.2\.`, ip)
_pf_sdnr_reserved(ip) if regex.match(`^198\.51\.100\.`, ip)
_pf_sdnr_reserved(ip) if regex.match(`^203\.0\.113\.`, ip)

violation contains make_diag_full("pf-servicediscovery-instance-healthcheck-forbids-nonroutable-ipv4", "ERROR", name,
	"Properties.InstanceAttributes.AWS_INSTANCE_IPV4",
	sprintf("AWS_INSTANCE_IPV4 %v is in a reserved range, and service '%v' health-checks its instances; RegisterInstance fails with \"IPv4 address %v is forbidden for healthChecks\"", [ip, svc, ip]),
	"Register a publicly routable IPv4 address, or drop HealthCheckConfig from the service",
	"https://docs.aws.amazon.com/cloud-map/latest/api/API_HealthCheckConfig.html") if {
	some name in resources_of_type("AWS::ServiceDiscovery::Instance")
	svc := _pf_sd_inst_svc(name)
	is_object(_pf_sd_healthcheck(svc))
	ip := object.get(_pf_sd_attrs(name), "AWS_INSTANCE_IPV4", null)
	is_string(ip)
	_pf_sdnr_reserved(ip)
}
