package cdk_preflight

import rego.v1

# "When replication is enabled, role cannot be empty." Measured 2026-09-07,
# events:CreateEndpoint, us-east-1. Replication defaults to ENABLED, but only
# an explicit ENABLED is reported here — that is what was measured.
violation contains make_diag_full("pf-events-endpoint-replication-role", "ERROR", name,
	"Properties.RoleArn",
	"ReplicationConfig is ENABLED but no RoleArn is set; CreateEndpoint fails with \"When replication is enabled, role cannot be empty\"",
	"Set RoleArn to a role EventBridge can assume, or disable replication",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-endpoint.html") if {
	some name in resources_of_type("AWS::Events::Endpoint")
	resolve(name, "Properties.ReplicationConfig.State") == "ENABLED"
	object.get(input.resources[name].properties, "RoleArn", "__pf_absent") == "__pf_absent"
}
