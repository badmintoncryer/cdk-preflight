package cdk_preflight

import rego.v1

_pf_lemta_fix := "Create an EFS mount target in every AZ the function has a subnet in"

_pf_lemta_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-function.html"

violation contains make_diag_full("pf-lambda-efs-mount-target-every-az", "ERROR", name,
	"Properties.VpcConfig.SubnetIds",
	sprintf("a subnet in '%v' with no EFS mount target in that AZ; the mount is resolved per availability zone and the create fails with \"EFS mount target for the file system is not available\"", [az]),
	_pf_lemta_fix, _pf_lemta_url) if {
	some name in _pf_lam_fn
	_pf_lam_has(name, "FileSystemConfigs")
	count(_pf_lam_mt_azs) > 0
	cfg := _pf_lam_vpccfg(name)
	some sub in _pf_lam_list(object.get(cfg, "SubnetIds", []))
	az := object.get(_pf_lam_res_props(_pf_lam_ref(sub)), "AvailabilityZone", "__pf_absent")
	az != "__pf_absent"
	not az in _pf_lam_mt_azs
}
