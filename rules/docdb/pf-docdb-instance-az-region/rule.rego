package cdk_preflight

import rego.v1

# Silent when the app has no concrete region (data.cdk_preflight.deploy_region is only
# injected in enforce mode with a concrete env) and for AZs wired via Fn::Select/Fn::GetAZs.
violation contains make_diag_full("pf-docdb-instance-az-region", "ERROR", name,
	"Properties.AvailabilityZone",
	sprintf("'%s' is not an Availability Zone of '%s', the region this stack deploys to; CreateDBInstance rejects it", [az, region]),
	"Write the zone as the deploy region plus a letter, e.g. Fn::Select over Fn::GetAZs",
	"https://docs.aws.amazon.com/documentdb/latest/developerguide/API_CreateDBInstance.html") if {
	region := data.cdk_preflight.deploy_region
	some name in resources_of_type("AWS::DocDB::DBInstance")
	az := _pf_docdb_lit(name, "Properties.AvailabilityZone")
	not startswith(az, region)
}
