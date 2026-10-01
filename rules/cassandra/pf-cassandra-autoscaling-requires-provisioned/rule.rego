package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cassandra-autoscaling-requires-provisioned", "ERROR", name, "Properties.AutoScalingSpecifications",
	"AutoScalingSpecifications is set on an ON_DEMAND table (BillingMode defaults to ON_DEMAND); Keyspaces answers \"PAY_PER_REQUEST throughput mode should not have AUTOSCALING_SETTINGS\"",
	"Set BillingMode.Mode to PROVISIONED with ProvisionedThroughput, or remove AutoScalingSpecifications",
	"https://docs.aws.amazon.com/keyspaces/latest/devguide/autoscaling.html") if {
	some name in resources_of_type("AWS::Cassandra::Table")
	is_object(object.get(input.resources[name].properties, "AutoScalingSpecifications", null))
	_pf_cass_mode(name) == "ON_DEMAND"
}
