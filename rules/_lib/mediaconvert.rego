package cdk_preflight

import rego.v1

# MediaConvert: Preset / JobTemplate の SettingsJson を読む共通部品（診断は出さない）。
#
# SettingsJson は CFN スキーマ上は自由形式のオブジェクトで、メンバー名は SDK と同じ PascalCase。
# ここから先はどれも「リテラルのオブジェクト / 配列」だけを返す。Fn::If / Ref / GetAtt / Sub の
# マーカーを含む節は載らないので、実 CDK テンプレートでは黙る。制約の出典と実測は
# ~/cdk-preflight-surveys/mediaconvert/（api-raw.jsonl）。

_pf_mclib_lit(o) if {
	is_object(o)
	object.get(o, "__kind", "_") == "_"
	object.get(o, "__dynamic", "_") == "_"
	object.get(o, "__conditional", "_") == "_"
}

_pf_mclib_settings(rn, rt) := s if {
	rn in resources_of_type(rt)
	p := input.resources[rn].properties
	is_object(p)
	s := p.SettingsJson
	_pf_mclib_lit(s)
}

# Preset: VideoDescription / CodecSettings / コンテナ
_pf_mclib_vd(rn) := vd if {
	s := _pf_mclib_settings(rn, "AWS::MediaConvert::Preset")
	vd := s.VideoDescription
	_pf_mclib_lit(vd)
}

_pf_mclib_vcs(rn) := cs if {
	vd := _pf_mclib_vd(rn)
	cs := vd.CodecSettings
	_pf_mclib_lit(cs)
}

_pf_mclib_codec(rn) := c if {
	cs := _pf_mclib_vcs(rn)
	c := cs.Codec
	is_string(c)
}

_pf_mclib_container(rn) := c if {
	s := _pf_mclib_settings(rn, "AWS::MediaConvert::Preset")
	cont := s.ContainerSettings
	_pf_mclib_lit(cont)
	c := cont.Container
	is_string(c)
}

# Preset: ColorCorrector（VideoPreprocessors の中）
_pf_mclib_cc(rn) := cc if {
	vd := _pf_mclib_vd(rn)
	vp := vd.VideoPreprocessors
	_pf_mclib_lit(vp)
	cc := vp.ColorCorrector
	_pf_mclib_lit(cc)
}

# Preset: AudioDescriptions の各要素（リテラルのものだけ）
_pf_mclib_ads contains {"rn": rn, "i": i, "ad": ad} if {
	some rn in resources_of_type("AWS::MediaConvert::Preset")
	s := _pf_mclib_settings(rn, "AWS::MediaConvert::Preset")
	ads := s.AudioDescriptions
	is_array(ads)
	some i, ad in ads
	_pf_mclib_lit(ad)
}

# Preset: AAC の AacSettings（Codec が AAC でリテラル）
_pf_mclib_aac contains {"rn": rn, "i": i, "aac": aac} if {
	some a in _pf_mclib_ads
	rn := a.rn
	i := a.i
	cs := a.ad.CodecSettings
	_pf_mclib_lit(cs)
	cs.Codec == "AAC"
	aac := cs.AacSettings
	_pf_mclib_lit(aac)
}

# Preset: RemixSettings
_pf_mclib_remix contains {"rn": rn, "i": i, "rs": rs} if {
	some a in _pf_mclib_ads
	rn := a.rn
	i := a.i
	rs := a.ad.RemixSettings
	_pf_mclib_lit(rs)
}

# JobTemplate: OutputGroups の各要素（OutputGroupSettings までリテラルのものだけ）
_pf_mclib_groups contains {"rn": rn, "i": i, "g": g, "gs": gs} if {
	some rn in resources_of_type("AWS::MediaConvert::JobTemplate")
	s := _pf_mclib_settings(rn, "AWS::MediaConvert::JobTemplate")
	ogs := s.OutputGroups
	is_array(ogs)
	some i, g in ogs
	_pf_mclib_lit(g)
	gs := g.OutputGroupSettings
	_pf_mclib_lit(gs)
}

# AAC CBR の許容表（ug/aac-support.html の CBR 表。LC / HEV1 / HEV2 のみ、XHE は含めない）。
# キーは "<CodecProfile>|<コーディングモード>|<SampleRate>"、値は [最小, 最大] ビットレート。
# 表にないキーはサンプルレートが不正、範囲外は Bitrate が不正（サーバーは範囲 min-max で報告する）。
_pf_mclib_aac_cbr := {
	"LC|1.0|8000": [8000, 14000],
	"LC|1.0|12000": [8000, 14000],
	"LC|1.0|16000": [8000, 28000],
	"LC|1.0|22050": [24000, 28000],
	"LC|1.0|24000": [24000, 28000],
	"LC|1.0|32000": [32000, 192000],
	"LC|1.0|44100": [56000, 256000],
	"LC|1.0|48000": [56000, 288000],
	"LC|1.0|88200": [288000, 288000],
	"LC|1.0|96000": [128000, 288000],
	"LC|2.0|8000": [16000, 20000],
	"LC|2.0|12000": [16000, 20000],
	"LC|2.0|16000": [16000, 32000],
	"LC|2.0|22050": [32000, 32000],
	"LC|2.0|24000": [32000, 32000],
	"LC|2.0|32000": [40000, 384000],
	"LC|2.0|44100": [64000, 512000],
	"LC|2.0|48000": [64000, 576000],
	"LC|2.0|88200": [576000, 576000],
	"LC|2.0|96000": [256000, 576000],
	"LC|5.1|32000": [160000, 768000],
	"LC|5.1|44100": [256000, 640000],
	"LC|5.1|48000": [256000, 768000],
	"LC|5.1|96000": [640000, 768000],
	"HEV1|1.0|22050": [8000, 10000],
	"HEV1|1.0|24000": [8000, 10000],
	"HEV1|1.0|32000": [12000, 64000],
	"HEV1|1.0|44100": [20000, 64000],
	"HEV1|1.0|48000": [20000, 64000],
	"HEV1|2.0|32000": [16000, 128000],
	"HEV1|2.0|44100": [16000, 96000],
	"HEV1|2.0|48000": [16000, 128000],
	"HEV1|2.0|96000": [96000, 128000],
	"HEV1|5.1|32000": [64000, 320000],
	"HEV1|5.1|44100": [64000, 224000],
	"HEV1|5.1|48000": [64000, 320000],
	"HEV1|5.1|96000": [256000, 320000],
	"HEV2|2.0|22050": [8000, 10000],
	"HEV2|2.0|24000": [8000, 10000],
	"HEV2|2.0|32000": [12000, 64000],
	"HEV2|2.0|44100": [20000, 64000],
	"HEV2|2.0|48000": [20000, 64000],
}

_pf_mclib_aac_mode := {
	"CODING_MODE_1_0": "1.0",
	"CODING_MODE_2_0": "2.0",
	"CODING_MODE_5_1": "5.1",
}
