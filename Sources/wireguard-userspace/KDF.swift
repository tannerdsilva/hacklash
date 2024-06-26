import RAW

// internal func kdf(n:size_t, key:Key, data:borrowing [UInt8]) throws -> [Result32] {
// 	let workBuffer = UnsafeMutableBufferPointer<Result32>.allocate(capacity:n)
// 	defer { workBuffer.deallocate() }
// 	// find the entropy from the data
// 	let genKey:Result32 = try wgHmac(key:key, data:data)
// 	var previous:Result32 = genKey
// 	for i in 1...n {
// 		let input = [UInt8](unsafeUninitializedCapacity:MemoryLayout<Result32>.size + 1) { buffer, count in
// 			previous.RAW_encode(dest:buffer.baseAddress!)[0] = UInt8(i)
// 			count = MemoryLayout<Result32>.size + 1
// 		}
// 		let output: Result32 = try wgHmac(key:key, data:input)
// 		workBuffer[i-1] = output
// 		previous = output
// 	}
// 	return Array(workBuffer)
// }

internal func wgKDF<A>(key:Key, data:borrowing A, returning:(Result32).Type) throws -> Result32 where A:RAW_accessible {
	let workBuffer = UnsafeMutableBufferPointer<Result32>.allocate(capacity:1)
	defer { workBuffer.deallocate() }
	// find the entropy from the data
	let genKey:Result32 = try wgHmac(key:key, data:data)
	var previous:Result32 = genKey
	let input = [UInt8](unsafeUninitializedCapacity:MemoryLayout<Result32>.size + 1) { buffer, count in
		previous.RAW_encode(dest:buffer.baseAddress!)[0] = UInt8(1)
		count = MemoryLayout<Result32>.size + 1
	}
	let output: Result32 = try wgHmac(key:key, data:input)
	workBuffer[0] = output
	previous = output
	return workBuffer[0]
}

internal func wgKDF<A>(key:Key, data:borrowing A, returning:(Result32, Result32).Type) throws -> (Result32, Result32) where A:RAW_accessible {
	let workBuffer = UnsafeMutableBufferPointer<Result32>.allocate(capacity:2)
	defer { workBuffer.deallocate() }
	// find the entropy from the data
	let genKey:Result32 = try wgHmac(key:key, data:data)
	var previous:Result32 = genKey
	for i in 1...2 {
		let input = [UInt8](unsafeUninitializedCapacity:MemoryLayout<Result32>.size + 1) { buffer, count in
			previous.RAW_encode(dest:buffer.baseAddress!)[0] = UInt8(i)
			count = MemoryLayout<Result32>.size + 1
		}
		let output:Result32 = try wgHmac(key:key, data:input)
		workBuffer[i-1] = output
		previous = output
	}
	return (workBuffer[0], workBuffer[1])
}