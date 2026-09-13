package cdk_preflight

import rego.v1

# Glue reads a bare path as a bucket-relative s3:// location, so "data/in" is
# accepted; only a leading slash is rejected outright.
violation contains make_diag_full("pf-glue-crawler-s3-target-path", "ERROR", name,
	sprintf("Properties.Targets.S3Targets.%d.Path", [i]),
	sprintf("S3 target Path '%s' starts with '/'; CreateCrawler fails with \"Invalid S3 Target Path\"", [p]),
	"Use an Amazon S3 location, e.g. s3://my-bucket/prefix/",
	"https://docs.aws.amazon.com/glue/latest/webapi/API_CreateCrawler.html") if {
	some name in resources_of_type("AWS::Glue::Crawler")
	arr := object.get(_pf_gluelib_targets(name), "S3Targets", [])
	is_array(arr)
	some i, t in arr
	is_object(t)
	p := object.get(t, "Path", null)
	_pf_gluelib_lit(p)
	startswith(p, "/")
}
