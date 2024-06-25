import RAW

@RAW_staticbuff(bytes:8)
@RAW_staticbuff_fixedwidthinteger_type<UInt64>(bigEndian:true)
public struct _uint64_be:Sendable {}

@RAW_staticbuff(bytes:4)
@RAW_staticbuff_fixedwidthinteger_type<UInt32>(bigEndian:true)
public struct _uint32_be:Sendable {}

@RAW_staticbuff(concat:_uint64_be, _uint32_be)
public struct TAI64N:Sendable {
	let seconds:_uint64_be
	let nano:_uint32_be
}
