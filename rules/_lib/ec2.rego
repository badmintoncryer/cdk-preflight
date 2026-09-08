package cdk_preflight

import rego.v1

# エンジンに net.cidr_* ビルトインは無い（1.7.0-beta で実測、rules/_lib/efs.rego
# にも同じ注記がある）ので IPv4 のアドレス演算を自前で持つ。pow ビルトインも
# 無いため 2^n は表で引く。IPv6 は扱わない（呼び出し側が ":" の有無で弾く）。
_pf_ec2lib_pow2 := {0: 1, 1: 2, 2: 4, 3: 8, 4: 16, 5: 32, 6: 64, 7: 128, 8: 256, 9: 512, 10: 1024, 11: 2048, 12: 4096, 13: 8192, 14: 16384, 15: 32768, 16: 65536, 17: 131072, 18: 262144, 19: 524288, 20: 1048576, 21: 2097152, 22: 4194304, 23: 8388608, 24: 16777216, 25: 33554432, 26: 67108864, 27: 134217728, 28: 268435456, 29: 536870912, 30: 1073741824, 31: 2147483648, 32: 4294967296}

_pf_ec2lib_ip_int(s) := n if {
	parts := split(s, ".")
	count(parts) == 4
	nums := [to_number(p) | some p in parts]
	every x in nums {
		x >= 0
		x <= 255
	}
	n := ((nums[0] * 16777216) + (nums[1] * 65536)) + ((nums[2] * 256) + nums[3])
}

# [ネットワークアドレス, ブロックサイズ] を返す。ホストビットが立っていても
# 切り捨てて正規化するので "10.0.0.5/24" は "10.0.0.0/24" と同じ結果になる。
_pf_ec2lib_cidr(s) := [start, size] if {
	parts := split(s, "/")
	count(parts) == 2
	base := _pf_ec2lib_ip_int(parts[0])
	p := to_number(parts[1])
	size := _pf_ec2lib_pow2[32 - p]
	start := floor(base / size) * size
}

_pf_ec2lib_cidr_has_ip(cidr, ip) if {
	c := _pf_ec2lib_cidr(cidr)
	n := _pf_ec2lib_ip_int(ip)
	n >= c[0]
	n < c[0] + c[1]
}

_pf_ec2lib_cidr_overlap(a, b) if {
	x := _pf_ec2lib_cidr(a)
	y := _pf_ec2lib_cidr(b)
	x[0] < y[0] + y[1]
	y[0] < x[0] + x[1]
}

# プロパティ不在の証明（AGENTS.md の sanctioned exception）
_pf_ec2lib_absent(name, key) if {
	props := input.resources[name].properties
	is_object(props)
	object.get(props, key, "__pf_absent") == "__pf_absent"
}
