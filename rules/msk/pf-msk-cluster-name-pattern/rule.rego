package cdk_preflight

import rego.v1

# ClusterName matches ^[0-9A-Za-z][0-9A-Za-z-]*$ - no underscores, no dots, no leading hyphen.
# The engine's schema carries the 64-character maximum (F3033) but no pattern, and CreateCluster
# answers with "The parameter value contains one or more characters that are not valid. ...
# InvalidParameter: clusterName" without repeating the pattern.
violation contains make_diag_full("pf-msk-cluster-name-pattern", "ERROR", name,
	"Properties.ClusterName",
	sprintf("cluster name '%s' is not alphanumeric-with-hyphens; the create fails with \"The parameter value contains one or more characters that are not valid\"", [n]),
	"Use only A-Z, a-z and 0-9, plus hyphens after the first character",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-cluster.html") if {
	some name in resources_of_type("AWS::MSK::Cluster")
	n := resolve(name, "Properties.ClusterName")
	is_string(n)
	not regex.match(`^[0-9A-Za-z][0-9A-Za-z-]*$`, n)
}
