package cdk_preflight

import rego.v1

# The bundled registry schema types ScanRate as a bare number.
_pf_gluecsr_bad(r) if r < 0.1

_pf_gluecsr_bad(r) if r > 1.5

violation contains make_diag_full("pf-glue-crawler-dynamodb-scan-rate", "ERROR", name,
	sprintf("Properties.Targets.DynamoDBTargets.%d.ScanRate", [i]),
	sprintf("ScanRate %v is outside 0.1-1.5; CreateCrawler fails with \"Invalid scan rate value. Valid values are between 0.1 to 1.5\"", [r]),
	"Use a ScanRate between 0.1 and 1.5 (the fraction of the table's read capacity the crawler may use), or leave it out",
	"https://docs.aws.amazon.com/glue/latest/webapi/API_CreateCrawler.html") if {
	some name in resources_of_type("AWS::Glue::Crawler")
	arr := object.get(_pf_gluelib_targets(name), "DynamoDBTargets", [])
	is_array(arr)
	some i, t in arr
	is_object(t)
	raw := object.get(t, "ScanRate", null)
	raw != null
	r := to_number(raw)
	_pf_gluecsr_bad(r)
}
