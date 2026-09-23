package cdk_preflight

import rego.v1

# 4 and 8 are both valid (the 4-8 band moves in steps of 4); the rule only judges the
# band above 8, where every valid value (8-512 in steps of 8, 512-1024 in steps of 32)
# is a multiple of 8. Values below 4 belong to pf-redshiftserverless-base-capacity-floor.
violation contains make_diag_full("pf-redshiftserverless-base-capacity-step", "ERROR", name,
	"Properties.BaseCapacity",
	sprintf("BaseCapacity %v is above 8 RPUs but not a multiple of 8; CreateWorkgroup fails with \"The base capacity must be a multiple of 8.\"", [n]),
	"Above 8 RPUs, BaseCapacity moves in steps of 8 (16, 24, ..., 512; 32-RPU steps above 512 where the region allows it)",
	"https://docs.aws.amazon.com/redshift/latest/mgmt/serverless-capacity.html") if {
	some name in resources_of_type("AWS::RedshiftServerless::Workgroup")
	n := to_number(resolve(name, "Properties.BaseCapacity"))
	n > 8
	n % 8 != 0
}
