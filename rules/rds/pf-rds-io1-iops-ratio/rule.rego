package cdk_preflight

import rego.v1

# Only the benched engine/type pair; the historical 64000 IOPS cap is
# gone (80000 deployed clean at ratio 40 on 2026-09-03).
violation contains make_diag_full("pf-rds-io1-iops-ratio", "ERROR", name,
	"Properties.Iops",
	sprintf("Iops %v is %v per GiB for %v GiB; postgres io1 allows at most 50 (\"Invalid iops to storage (GiB) ratio\")", [n, n / s, s]),
	"Keep Iops at or below 50 x AllocatedStorage",
	"https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/CHAP_Storage.html") if {
	some name in resources_of_type("AWS::RDS::DBInstance")
	resolve(name, "Properties.Engine") == "postgres"
	resolve(name, "Properties.StorageType") == "io1"
	n := to_number(resolve(name, "Properties.Iops"))
	s := to_number(resolve(name, "Properties.AllocatedStorage"))
	s > 0
	n > s * 50
}
