package cdk_preflight

import rego.v1

_pf_asgwphe_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutWarmPool.html"

_pf_asgwphe_root(d) if d in ["/dev/xvda", "/dev/sda1"]

violation contains make_diag_full("pf-asg-wp-hibernated-requires-encrypted-root", "ERROR", name,
	sprintf("Properties.LaunchTemplateData.BlockDeviceMappings.%d.Ebs.Encrypted", [i]),
	sprintf("warm pool %s hibernates, but the root volume of launch template %s is not encrypted; the warm pool create fails with \"For hibernation, the root device volume must be encrypted.\"", [name, lt]),
	"Set Encrypted: true on the root block device mapping", _pf_asgwphe_url) if {
	some name in resources_of_type("AWS::AutoScaling::WarmPool")
	resolve(name, "Properties.PoolState") == "Hibernated"
	lt := _pf_aslib_lt(_pf_aslib_group(name))
	some i, m in _pf_aslib_arr(lt, ["LaunchTemplateData", "BlockDeviceMappings"])
	is_object(m)
	_pf_asgwphe_root(object.get(m, "DeviceName", ""))
	ebs := object.get(m, "Ebs", null)
	is_object(ebs)
	e := object.get(ebs, "Encrypted", false)
	not is_object(e)
	e != true
}
