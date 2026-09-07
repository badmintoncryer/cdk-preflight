package cdk_preflight

import rego.v1

# A property value that is a user-written literal string (a Ref/GetAtt to a
# template resource resolves to the target logical id, which is not a name).
_pf_s3xlib_lit(name, path) := s if {
	s := resolve(name, path)
	is_string(s)
	not input.resources[s]
}

# The zone id embedded in a directory bucket name (`<base>--<zone>--x-s3`)
# or an S3 Express access point name (`<base>--<zone>--xa-s3`).
_pf_s3xlib_zone(s) := z if {
	parts := split(s, "--")
	count(parts) == 3
	parts[2] in {"x-s3", "xa-s3"}
	z := parts[1]
}

# The bucket name behind a property that takes either the literal name or a Ref.
_pf_s3xlib_bucketname(name, path) := s if {
	s := _pf_s3xlib_lit(name, path)
}

_pf_s3xlib_bucketname(name, path) := s if {
	t := resolve(name, path)
	t in resources_of_type("AWS::S3Express::DirectoryBucket")
	s := _pf_s3xlib_lit(t, "Properties.BucketName")
}

_pf_s3xlib_dir := {
	"east": "e",
	"west": "w",
	"north": "n",
	"south": "s",
	"central": "c",
	"northeast": "ne",
	"northwest": "nw",
	"southeast": "se",
	"southwest": "sw",
}

# us-west-2 -> usw2, ap-northeast-1 -> apne1: the prefix every zone id in that
# region carries.
_pf_s3xlib_zoneprefix(region) := p if {
	parts := split(region, "-")
	count(parts) == 3
	d := _pf_s3xlib_dir[parts[1]]
	p := concat("", [parts[0], d, parts[2]])
}
