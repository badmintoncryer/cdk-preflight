package cdk_preflight

import rego.v1

_pf_efsfsref_url := "https://docs.aws.amazon.com/efs/latest/APIReference/API_CreateAccessPoint.html"

_pf_efsfsref_fix := "Reference the file system with Ref / Fn::GetAtt (or its id), or use an ARN of the region this stack deploys to — EFS has no cross-region mount targets or access points"

violation contains make_diag_full("pf-efs-file-system-reference-region", "ERROR", name,
	"Properties.FileSystemId",
	sprintf("the file system ARN is in region '%s' but this stack deploys to '%s'; the create call fails with \"The resource ARN belongs to a different region.\"", [parts[3], region]),
	_pf_efsfsref_fix, _pf_efsfsref_url) if {
	region := data.cdk_preflight.deploy_region
	some t in ["AWS::EFS::MountTarget", "AWS::EFS::AccessPoint"]
	some name in resources_of_type(t)
	parts := _pf_efslib_arn(resolve(name, "Properties.FileSystemId"))
	parts[2] == "elasticfilesystem"
	parts[3] != region
}
