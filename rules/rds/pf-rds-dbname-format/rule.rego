package cdk_preflight

import rego.v1

# Only the letter-start half of the service message is claimed: the
# "only alphanumeric" half is measurably wrong (bench_db deploys).
violation contains make_diag_full("pf-rds-dbname-format", "ERROR", name,
	"Properties.DBName",
	sprintf("DBName '%s' does not begin with a letter (\"DBName must begin with a letter\"); the CreateDBInstance call fails", [dn]),
	"Start the database name with a letter",
	"https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_CreateDBInstance.html") if {
	some name in resources_of_type("AWS::RDS::DBInstance")
	resolve(name, "Properties.Engine") == "postgres"
	dn := resolve(name, "Properties.DBName")
	is_string(dn)
	not regex.match(`^[a-zA-Z]`, dn)
}
