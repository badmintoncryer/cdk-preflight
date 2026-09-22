package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-redshiftserverless-max-capacity-ge-base", "ERROR", name,
	"Properties.MaxCapacity",
	sprintf("MaxCapacity %v is lower than BaseCapacity %v; CreateWorkgroup fails with \"The base capacity can't be more than 24 RPUs.\" (the service words it from the base side)", [m, b]),
	"Raise MaxCapacity to at least BaseCapacity, or lower BaseCapacity",
	"https://docs.aws.amazon.com/redshift-serverless/latest/APIReference/API_CreateWorkgroup.html") if {
	some name in resources_of_type("AWS::RedshiftServerless::Workgroup")
	b := to_number(resolve(name, "Properties.BaseCapacity"))
	m := to_number(resolve(name, "Properties.MaxCapacity"))
	m < b
}
