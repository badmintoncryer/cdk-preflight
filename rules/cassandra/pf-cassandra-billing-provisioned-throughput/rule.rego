package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cassandra-billing-provisioned-throughput", "ERROR", name, "Properties.BillingMode.ProvisionedThroughput",
	"BillingMode.Mode is ON_DEMAND but ProvisionedThroughput is set; the table create fails with \"BillingMode is invalid\"",
	"Remove ProvisionedThroughput, or set Mode to PROVISIONED",
	"https://docs.aws.amazon.com/keyspaces/latest/devguide/ReadWriteCapacityMode.html") if {
	some name in resources_of_type("AWS::Cassandra::Table")
	_pf_cass_mode(name) == "ON_DEMAND"
	bm := object.get(input.resources[name].properties, "BillingMode", null)
	is_object(bm)
	object.get(bm, "ProvisionedThroughput", null) != null
}

violation contains make_diag_full("pf-cassandra-billing-provisioned-throughput", "ERROR", name, "Properties.BillingMode",
	"BillingMode.Mode is PROVISIONED but ProvisionedThroughput is missing; the table create fails with \"BillingMode is invalid\"",
	"Add ProvisionedThroughput with ReadCapacityUnits and WriteCapacityUnits",
	"https://docs.aws.amazon.com/keyspaces/latest/devguide/ReadWriteCapacityMode.html") if {
	some name in resources_of_type("AWS::Cassandra::Table")
	_pf_cass_mode(name) == "PROVISIONED"
	bm := object.get(input.resources[name].properties, "BillingMode", null)
	object.get(bm, "ProvisionedThroughput", null) == null
}
