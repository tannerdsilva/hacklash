import RAW
import RAW_dh25519
import RAW_chachapoly

internal func dhGenerate() throws -> (PublicKey, PrivateKey) {
	let privateKey = try PrivateKey()
	let publicKey = PublicKey(privateKey)
	return (publicKey, privateKey)
}

internal func dhKeyExchange(privateKey: PrivateKey, publicKey: PublicKey) throws -> SharedKey {
	return SharedKey.compute(privateKey: privateKey, publicKey: publicKey)
}
