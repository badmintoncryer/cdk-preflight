package cdk_preflight

import rego.v1

_pf_efsaz_url := "https://docs.aws.amazon.com/efs/latest/APIReference/API_CreateFileSystem.html"

_pf_efsaz_fix := "Write the One Zone name as the deploy region plus a letter, e.g. Fn::Select over Fn::GetAZs or Fn::Sub \"${AWS::Region}a\""

violation contains make_diag_full("pf-efs-availability-zone-region", "ERROR", name,
	"Properties.AvailabilityZoneName",
	sprintf("'%s' is not an Availability Zone of '%s', the region this stack deploys to; CreateFileSystem fails with \"Invalid Availability Zone Name provided.\"", [az, region]),
	_pf_efsaz_fix, _pf_efsaz_url) if {
	region := data.cdk_preflight.deploy_region
	some name in resources_of_type("AWS::EFS::FileSystem")
	az := resolve(name, "Properties.AvailabilityZoneName")
	is_string(az)
	not input.resources[az]
	not startswith(az, region)
}
