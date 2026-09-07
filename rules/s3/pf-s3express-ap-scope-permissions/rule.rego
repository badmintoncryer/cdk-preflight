package cdk_preflight

import rego.v1

_pf_s3xaps_fix := "List the permissions without the s3: prefix, e.g. GetObject instead of s3:GetObject"

_pf_s3xaps_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3express-accesspoint-scope.html"

_pf_s3xaps_allowed := {
	"GetObject",
	"GetObjectAttributes",
	"ListMultipartUploadParts",
	"ListBucket",
	"PutObject",
	"DeleteObject",
	"AbortMultipartUpload",
	"*",
}

violation contains make_diag_full("pf-s3express-ap-scope-permissions", "ERROR", name,
	sprintf("Properties.Scope.Permissions.%d", [p.index]),
	sprintf("'%v' is not an access point scope permission; the scope takes bare API names such as GetObject, not s3: actions", [p.value]),
	_pf_s3xaps_fix, _pf_s3xaps_url) if {
	some name in resources_of_type("AWS::S3Express::AccessPoint")
	some p in flatten_list(name, "Properties.Scope.Permissions")
	is_string(p.value)
	not _pf_s3xaps_allowed[p.value]
}
