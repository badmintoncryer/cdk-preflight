package cdk_preflight

import rego.v1

_pf_udsz_fix := "Keep user data under 16384 bytes; move large payloads to S3 and fetch them from a small bootstrap script"

_pf_udsz_url := "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-add-user-data.html"

_pf_udsz_limit := 16384

# base64 文字列のデコード後バイト数（パディング考慮）
_pf_udsz_decoded(s) := ((count(s) * 3) / 4) - 2 if endswith(s, "==")

_pf_udsz_decoded(s) := ((count(s) * 3) / 4) - 1 if {
	endswith(s, "=")
	not endswith(s, "==")
}

_pf_udsz_decoded(s) := (count(s) * 3) / 4 if not endswith(s, "=")

_pf_udsz_paths := {
	"AWS::EC2::Instance": "Properties.UserData",
	"AWS::EC2::LaunchTemplate": "Properties.LaunchTemplateData.UserData",
}

# UserData がリテラル base64 文字列のケース
violation contains make_diag_full("pf-ec2-userdata-size", "ERROR", name, p,
	sprintf("UserData decodes to about %v bytes, but EC2 limits user data to %d bytes; RunInstances fails at deploy time", [size, _pf_udsz_limit]),
	_pf_udsz_fix, _pf_udsz_url) if {
	some rtype, p in _pf_udsz_paths
	some name in resources_of_type(rtype)
	ud := resolve(name, p)
	is_string(ud)
	size := _pf_udsz_decoded(ud)
	size > _pf_udsz_limit
}

# UserData が {"Fn::Base64": "<literal>"} のケース（エンコード前の生バイト数で判定）
violation contains make_diag_full("pf-ec2-userdata-size", "ERROR", name, p,
	sprintf("UserData is %d bytes before base64 encoding, but EC2 limits user data to %d bytes; RunInstances fails at deploy time", [count(inner), _pf_udsz_limit]),
	_pf_udsz_fix, _pf_udsz_url) if {
	some rtype, p in _pf_udsz_paths
	some name in resources_of_type(rtype)
	ud := resolve(name, p)
	is_object(ud)
	inner := object.get(ud, "Fn::Base64", null)
	is_string(inner)
	count(inner) > _pf_udsz_limit
}
