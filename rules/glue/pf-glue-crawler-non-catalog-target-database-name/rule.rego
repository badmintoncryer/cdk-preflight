package cdk_preflight

import rego.v1

# Catalog targets carry their own database, so only the other target kinds make
# DatabaseName mandatory.
_pf_gluecrdb_other := ["S3Targets", "JdbcTargets", "MongoDBTargets", "DynamoDBTargets", "DeltaTargets", "IcebergTargets", "HudiTargets"]

violation contains make_diag_full("pf-glue-crawler-non-catalog-target-database-name", "ERROR", name,
	"Properties.DatabaseName",
	sprintf("The crawler has %s but no DatabaseName; CreateCrawler fails with \"You must provide the DatabaseName parameter when you specify a non-catalog targeted crawler.\"", [k]),
	"Set DatabaseName to the catalog database the crawler writes into",
	"https://docs.aws.amazon.com/glue/latest/webapi/API_CreateCrawler.html") if {
	some name in resources_of_type("AWS::Glue::Crawler")
	_pf_gluelib_absent(name, "DatabaseName")
	some k in _pf_gluecrdb_other
	arr := object.get(_pf_gluelib_targets(name), k, [])
	is_array(arr)
	count(arr) > 0
}
