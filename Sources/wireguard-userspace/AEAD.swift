import RAW
import RAW_dh25519
import RAW_chachapoly

@RAW_staticbuff(bytes:4)
@RAW_staticbuff_fixedwidthinteger_type<UInt32>(bigEndian:false)
internal struct Zeros:Sendable, ExpressibleByIntegerLiteral {}

@RAW_staticbuff(bytes:8)
@RAW_staticbuff_fixedwidthinteger_type<UInt64>(bigEndian:false)
internal struct Counter:Sendable {}

@RAW_staticbuff(concat:Zeros, Counter)
internal struct CountedNonce:Sendable {
	internal let zeros:Zeros
	internal let counter:Counter
	internal init(counter:UInt64) {
		self.zeros = 0
		self.counter = Counter(RAW_native:counter)
	}
}

internal func aeadEncrypt(key:Key32, counter:UInt64, text:borrowing [UInt8], aad:consuming [UInt8]) throws -> ([UInt8], Tag) {
	let cipherText = UnsafeMutableBufferPointer<UInt8>.allocate(capacity:text.count)
	defer { cipherText.deallocate() }
	var context = RAW_chachapoly.Context(key:key)
	let ourTag = try text.RAW_access { textBuff in
		try aad.RAW_access { aadBuff in
			return try CountedNonce(counter: counter).RAW_access_staticbuff { 
				try context.encrypt(nonce:$0.load(as:Nonce.self), associatedData:aadBuff, inputData:textBuff, output:cipherText.baseAddress!)
			}
		}
	}
	return (Array(cipherText), ourTag)
}

internal func aeadDecrypt(key:Key32, counter:UInt64, cipherText:borrowing [UInt8], aad:consuming [UInt8], tag:Tag) throws -> [UInt8] {
	let plainText = UnsafeMutableBufferPointer<UInt8>.allocate(capacity:cipherText.count)
	defer { plainText.deallocate() }
	var context = RAW_chachapoly.Context(key:key)
	try cipherText.RAW_access { cipherTextBuff in
		try aad.RAW_access { aadBuff in
			try CountedNonce(counter: counter).RAW_access_staticbuff { 
				try context.decrypt(tag:tag, nonce:$0.load(as:Nonce.self), associatedData:aadBuff, inputData:cipherTextBuff, output:plainText.baseAddress!)
			}
		}
	}
	return Array(plainText)
}