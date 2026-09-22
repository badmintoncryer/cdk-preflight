package cdk_preflight

import rego.v1

_pf_nepport_out(n) if n < 1150

_pf_nepport_out(n) if n > 65535

violation contains make_diag_full("pf-neptune-port-range", "ERROR", name,
	"Properties.DBPort",
	sprintf("DBPort %v is outside 1150-65535 (\"Invalid endpoint port 1149. Valid range is: 1150-65535\")", [n]),
	"Pick a port between 1150 and 65535",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-neptune-dbcluster.html") if {
	some name in resources_of_type("AWS::Neptune::DBCluster")
	n := to_number(resolve(name, "Properties.DBPort"))
	_pf_nepport_out(n)
}
