package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-rds-max-allocated-storage", "ERROR", name,
	"Properties.MaxAllocatedStorage",
	sprintf("MaxAllocatedStorage %v is not greater than AllocatedStorage %v (\"Max storage size must be greater than storage size\")", [mx, al]),
	"Raise MaxAllocatedStorage above AllocatedStorage",
	"https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_CreateDBInstance.html") if {
	some name in resources_of_type("AWS::RDS::DBInstance")
	mx := to_number(resolve(name, "Properties.MaxAllocatedStorage"))
	al := to_number(resolve(name, "Properties.AllocatedStorage"))
	mx <= al
}
