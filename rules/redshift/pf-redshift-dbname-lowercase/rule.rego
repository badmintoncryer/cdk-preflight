package cdk_preflight

import rego.v1

# The service message (phase B) is the source of truth: lowercase, letter first, and
# the characters a-z 0-9 _ + . @ -. The API doc's "alphanumeric only" is narrower than
# what CreateCluster accepts. Length is left to the engine schema.
violation contains make_diag_full("pf-redshift-dbname-lowercase", "ERROR", name,
	"Properties.DBName",
	sprintf("DBName '%s' is not a lowercase identifier starting with a letter; CreateCluster rejects it (\"DbName parameter must be lowercase, begin with a letter, contain only alphanumeric characters, underscore ('_'), plus sign ('+'), dot ('.'), at ('@'), or hyphen ('-')\")", [dn]),
	"Use a lowercase name that starts with a letter and contains only a-z, 0-9, _, +, ., @ and -",
	"https://docs.aws.amazon.com/redshift/latest/APIReference/API_CreateCluster.html") if {
	some name in resources_of_type("AWS::Redshift::Cluster")
	dn := _pf_redshiftlib_str(name, "DBName")
	not regex.match(`^[a-z][a-z0-9_+.@-]*$`, dn)
}
