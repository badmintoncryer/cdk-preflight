package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-redshiftserverless-base-capacity-floor", "ERROR", name,
	"Properties.BaseCapacity",
	sprintf("BaseCapacity %v is below the 4 RPU minimum; CreateWorkgroup fails with \"The base capacity can't be less than 4 RPUs.\"", [n]),
	"Set BaseCapacity to 4, 8, or a multiple of 8",
	"https://docs.aws.amazon.com/redshift/latest/mgmt/serverless-capacity.html") if {
	some name in resources_of_type("AWS::RedshiftServerless::Workgroup")
	n := to_number(resolve(name, "Properties.BaseCapacity"))
	n < 4
}
