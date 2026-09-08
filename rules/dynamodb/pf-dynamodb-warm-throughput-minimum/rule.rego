package cdk_preflight

import rego.v1

_pf_ddbwtm_url := "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/warm-throughput.html"

# The CFN schema's Minimum is 1, but warm throughput can only be raised above
# the table's initial values (12,000 read / 4,000 write units per second).
# Table-level WarmThroughput only; index-level values were not measured.
violation contains make_diag_full("pf-dynamodb-warm-throughput-minimum", "ERROR", name,
	"Properties.WarmThroughput.ReadUnitsPerSecond",
	sprintf("WarmThroughput.ReadUnitsPerSecond is %d; CreateTable fails with \"Requested ReadUnitsPerSecond for WarmThroughput for table is lower than initial throughput\" below 12000", [r]),
	"Use at least 12000 read units per second, or omit WarmThroughput to keep the default",
	_pf_ddbwtm_url) if {
	some name in resources_of_type("AWS::DynamoDB::Table")
	r := to_number(resolve(name, "Properties.WarmThroughput.ReadUnitsPerSecond"))
	r < 12000
}

violation contains make_diag_full("pf-dynamodb-warm-throughput-minimum", "ERROR", name,
	"Properties.WarmThroughput.WriteUnitsPerSecond",
	sprintf("WarmThroughput.WriteUnitsPerSecond is %d; CreateTable rejects anything below the initial 4000 write units per second", [w]),
	"Use at least 4000 write units per second, or omit WarmThroughput to keep the default",
	_pf_ddbwtm_url) if {
	some name in resources_of_type("AWS::DynamoDB::Table")
	w := to_number(resolve(name, "Properties.WarmThroughput.WriteUnitsPerSecond"))
	w < 4000
}
