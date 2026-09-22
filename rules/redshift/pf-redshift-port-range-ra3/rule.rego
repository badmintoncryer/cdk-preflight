package cdk_preflight

import rego.v1

# Only the RMS families (ra3 / rg) are bound to the two bands; dc2 takes 1150-65535 and
# is not judged. Port is judged as a literal number, tokens skip.
_pf_rsport_out(n) if n < 5431

_pf_rsport_out(n) if {
	n > 5455
	n < 8191
}

_pf_rsport_out(n) if n > 8215

violation contains make_diag_full("pf-redshift-port-range-ra3", "ERROR", name,
	"Properties.Port",
	sprintf("Port %v on node type %s is outside 5431-5455 and 8191-8215; CreateCluster rejects it for RG and RA3 node types", [n, nt]),
	"Use a port from 5431-5455 or 8191-8215 (the default is 5439), or omit Port",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-redshift-cluster.html") if {
	some name in resources_of_type("AWS::Redshift::Cluster")
	_pf_redshiftlib_rms(name)
	nt := _pf_redshiftlib_node_type(name)
	n := _pf_redshiftlib_num(name, "Port")
	_pf_rsport_out(n)
}
