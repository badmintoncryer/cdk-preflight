package cdk_preflight

import rego.v1

# Same name pattern as every other MSK entity: ^[0-9A-Za-z][0-9A-Za-z-]{0,}$. Underscores are the
# realistic mistake (they are legal in Kafka topic names and in CDK ids). The schema has no pattern
# for this property; CreateClusterV2 answers "The parameter value contains one or more characters
# that are not valid. ... InvalidParameter: clusterName".
violation contains make_diag_full("pf-msk-serverless-name-pattern", "ERROR", name,
	"Properties.ClusterName",
	sprintf("cluster name '%s' is not alphanumeric-with-hyphens; the create fails with \"The parameter value contains one or more characters that are not valid\"", [n]),
	"Use only A-Z, a-z and 0-9, plus hyphens after the first character",
	"https://docs.aws.amazon.com/msk/latest/developerguide/serverless.html") if {
	some name in resources_of_type("AWS::MSK::ServerlessCluster")
	n := resolve(name, "Properties.ClusterName")
	is_string(n)
	not regex.match(`^[0-9A-Za-z][0-9A-Za-z-]*$`, n)
}
