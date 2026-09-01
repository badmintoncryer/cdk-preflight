package cdk_preflight

import rego.v1

_pf_voliops_fix := "Match Iops/Throughput to the volume type: gp3 3000-80000 IOPS (max 500/GiB, throughput 125-2000 MiB/s and at most IOPS/4), io1 100-64000 (max 50/GiB), io2 100-256000 (max 1000/GiB); gp2/st1/sc1/standard accept neither property"

_pf_voliops_url := "https://docs.aws.amazon.com/ebs/latest/userguide/ebs-volume-types.html"

_pf_voliops_range := {"gp3": [3000, 80000], "io1": [100, 64000], "io2": [100, 256000]}

_pf_voliops_per_gib := {"gp3": 500, "io1": 50, "io2": 1000}

_pf_voliops_out(n, lo, hi) if n < lo

_pf_voliops_out(n, lo, hi) if n > hi

_pf_voliops_has_iops(name) if resolve(name, "Properties.Iops")

# IOPS が型ごとの絶対レンジ外
violation contains make_diag_full("pf-ec2-volume-iops", "ERROR", name, "Properties.Iops",
	sprintf("Iops %v is outside the supported range %d-%d for %s volumes", [n, r[0], r[1], vt]),
	_pf_voliops_fix, _pf_voliops_url) if {
	some name in resources_of_type("AWS::EC2::Volume")
	vt := resolve(name, "Properties.VolumeType")
	r := _pf_voliops_range[vt]
	n := to_number(resolve(name, "Properties.Iops"))
	_pf_voliops_out(n, r[0], r[1])
}

# IOPS : サイズ比の超過
violation contains make_diag_full("pf-ec2-volume-iops", "ERROR", name, "Properties.Iops",
	sprintf("Iops %v exceeds the maximum ratio of %d IOPS per GiB for %s (Size %v GiB allows at most %v)", [n, ratio, vt, s, s * ratio]),
	_pf_voliops_fix, _pf_voliops_url) if {
	some name in resources_of_type("AWS::EC2::Volume")
	vt := resolve(name, "Properties.VolumeType")
	ratio := _pf_voliops_per_gib[vt]
	n := to_number(resolve(name, "Properties.Iops"))
	s := to_number(resolve(name, "Properties.Size"))
	n > s * ratio
}

# Iops を受け付けない型に Iops を指定
violation contains make_diag_full("pf-ec2-volume-iops", "ERROR", name, "Properties.Iops",
	sprintf("Iops is not supported for %s volumes (valid only for gp3, io1, io2); EC2 rejects the CreateVolume call", [vt]),
	_pf_voliops_fix, _pf_voliops_url) if {
	some name in resources_of_type("AWS::EC2::Volume")
	vt := resolve(name, "Properties.VolumeType")
	vt in {"gp2", "st1", "sc1", "standard"}
	resolve(name, "Properties.Iops")
}

# Throughput は gp3 専用
violation contains make_diag_full("pf-ec2-volume-iops", "ERROR", name, "Properties.Throughput",
	sprintf("Throughput is not supported for %s volumes (valid only for gp3); EC2 rejects the CreateVolume call", [vt]),
	_pf_voliops_fix, _pf_voliops_url) if {
	some name in resources_of_type("AWS::EC2::Volume")
	vt := resolve(name, "Properties.VolumeType")
	is_string(vt)
	vt != "gp3"
	resolve(name, "Properties.Throughput")
}

# gp3 Throughput の絶対レンジ
violation contains make_diag_full("pf-ec2-volume-iops", "ERROR", name, "Properties.Throughput",
	sprintf("Throughput %v MiB/s is outside the supported range 125-2000 for gp3 volumes", [t]),
	_pf_voliops_fix, _pf_voliops_url) if {
	some name in resources_of_type("AWS::EC2::Volume")
	resolve(name, "Properties.VolumeType") == "gp3"
	t := to_number(resolve(name, "Properties.Throughput"))
	_pf_voliops_out(t, 125, 2000)
}

# gp3 Throughput : IOPS 比（最大 0.25 MiB/s per IOPS）
violation contains make_diag_full("pf-ec2-volume-iops", "ERROR", name, "Properties.Throughput",
	sprintf("Throughput %v MiB/s exceeds the maximum ratio of 0.25 MiB/s per provisioned IOPS (%v IOPS allows at most %v)", [t, n, n / 4]),
	_pf_voliops_fix, _pf_voliops_url) if {
	some name in resources_of_type("AWS::EC2::Volume")
	resolve(name, "Properties.VolumeType") == "gp3"
	t := to_number(resolve(name, "Properties.Throughput"))
	n := to_number(resolve(name, "Properties.Iops"))
	t * 4 > n
}

# gp3 で Iops 未指定（デフォルト 3000）のときの Throughput 比
violation contains make_diag_full("pf-ec2-volume-iops", "ERROR", name, "Properties.Throughput",
	sprintf("Throughput %v MiB/s exceeds 750, the maximum for the default 3000 IOPS (0.25 MiB/s per IOPS); provision Iops explicitly or lower the throughput", [t]),
	_pf_voliops_fix, _pf_voliops_url) if {
	some name in resources_of_type("AWS::EC2::Volume")
	resolve(name, "Properties.VolumeType") == "gp3"
	not _pf_voliops_has_iops(name)
	t := to_number(resolve(name, "Properties.Throughput"))
	t > 750
}
