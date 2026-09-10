package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-healthcheck-ipaddress-private-range", "ERROR", name,
	"Properties.HealthCheckConfig.IPAddress",
	sprintf("IPAddress %s is in a private, loopback, link-local, shared, documentation or multicast range; Route 53 rejects it as a forbidden address", [v]),
	"Use a public IP address, or check the endpoint by FullyQualifiedDomainName",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_HealthCheckConfig.html") if {
	some name in resources_of_type("AWS::Route53::HealthCheck")
	cfg := _pf_r53z_hcc(name)
	v := _pf_r53z_str(cfg, "IPAddress")
	regex.match(`^(0\.|10\.|127\.|169\.254\.|192\.168\.|192\.0\.0\.|192\.0\.2\.|192\.88\.99\.|198\.51\.100\.|203\.0\.113\.|198\.1[89]\.|172\.(1[6-9]|2[0-9]|3[01])\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.|(22[4-9]|23[0-9]|24[0-9]|25[0-5])\.|::1$|[fF][cCdD]|[fF][eE][89abAB])`, v)
}
