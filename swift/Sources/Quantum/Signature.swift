import CryptoKit
import Foundation

// MARK: - ML-DSA65

@_cdecl("swift_mldsa65_generate_keypair")
public func swiftMLDsa65GenerateKeypair(
    seed: UnsafeMutableRawPointer, publicKey: UnsafeMutableRawPointer
) -> Int32 {
    if #available(macOS 26, iOS 26, *) {
        do {
            let key = try MLDSA65.PrivateKey()
            let seedData = key.integrityCheckedRepresentation
            let pubData = key.publicKey.rawRepresentation

            seedData.withUnsafeBytes { bytes in
                seed.copyMemory(from: bytes.baseAddress!, byteCount: bytes.count)
            }
            pubData.withUnsafeBytes { bytes in
                publicKey.copyMemory(from: bytes.baseAddress!, byteCount: bytes.count)
            }
            return 0
        } catch {
            return -1
        }
    }
    return -1
}

@_cdecl("swift_mldsa65_sign")
public func swiftMLDsa65Sign(
    seed: UnsafeRawPointer,
    message: UnsafeRawPointer,
    messageLen: Int,
    signature: UnsafeMutableRawPointer,
    signatureLen: UnsafeMutablePointer<Int>
) -> Int32 {
    if #available(macOS 26, iOS 26, *) {
        do {
            let seedData = Data(bytes: seed, count: 64)
            let key = try MLDSA65.PrivateKey(integrityCheckedRepresentation: seedData)
            let msgData = Data(bytes: message, count: messageLen)
            let sigData = try key.signature(for: msgData)

            sigData.withUnsafeBytes { bytes in
                signature.copyMemory(from: bytes.baseAddress!, byteCount: bytes.count)
            }
            signatureLen.pointee = sigData.count
            return 0
        } catch {
            return -1
        }
    }
    return -1
}

@_cdecl("swift_mldsa65_verify")
public func swiftMLDsa65Verify(
    publicKey: UnsafeRawPointer,
    message: UnsafeRawPointer,
    messageLen: Int,
    signature: UnsafeRawPointer,
    signatureLen: Int
) -> Int32 {
    if #available(macOS 26, iOS 26, *) {
        do {
            let pubData = Data(bytes: publicKey, count: 1952)
            let key = try MLDSA65.PublicKey(rawRepresentation: pubData)
            let msgData = Data(bytes: message, count: messageLen)
            let sigData = Data(bytes: signature, count: signatureLen)

            return key.isValidSignature(sigData, for: msgData) ? 0 : 1
        } catch {
            return -1
        }
    }
    return -1
}

@_cdecl("swift_mldsa65_derive_public_key")
public func swiftMLDsa65DerivePublicKey(
    seed: UnsafeRawPointer, publicKey: UnsafeMutableRawPointer
) -> Int32 {
    if #available(macOS 26, iOS 26, *) {
        do {
            let seedData = Data(bytes: seed, count: 64)
            let key = try MLDSA65.PrivateKey(integrityCheckedRepresentation: seedData)
            let pubData = key.publicKey.rawRepresentation

            pubData.withUnsafeBytes { bytes in
                publicKey.copyMemory(from: bytes.baseAddress!, byteCount: bytes.count)
            }
            return 0
        } catch {
            return -1
        }
    }
    return -1
}

// MARK: - ML-DSA87

@_cdecl("swift_mldsa87_generate_keypair")
public func swiftMLDsa87GenerateKeypair(
    seed: UnsafeMutableRawPointer, publicKey: UnsafeMutableRawPointer
) -> Int32 {
    if #available(macOS 26, iOS 26, *) {
        do {
            let key = try MLDSA87.PrivateKey()
            let seedData = key.integrityCheckedRepresentation
            let pubData = key.publicKey.rawRepresentation

            seedData.withUnsafeBytes { bytes in
                seed.copyMemory(from: bytes.baseAddress!, byteCount: bytes.count)
            }
            pubData.withUnsafeBytes { bytes in
                publicKey.copyMemory(from: bytes.baseAddress!, byteCount: bytes.count)
            }
            return 0
        } catch {
            return -1
        }
    }
    return -1
}

@_cdecl("swift_mldsa87_sign")
public func swiftMLDsa87Sign(
    seed: UnsafeRawPointer,
    message: UnsafeRawPointer,
    messageLen: Int,
    signature: UnsafeMutableRawPointer,
    signatureLen: UnsafeMutablePointer<Int>
) -> Int32 {
    if #available(macOS 26, iOS 26, *) {
        do {
            let seedData = Data(bytes: seed, count: 64)
            let key = try MLDSA87.PrivateKey(integrityCheckedRepresentation: seedData)
            let msgData = Data(bytes: message, count: messageLen)
            let sigData = try key.signature(for: msgData)

            sigData.withUnsafeBytes { bytes in
                signature.copyMemory(from: bytes.baseAddress!, byteCount: bytes.count)
            }
            signatureLen.pointee = sigData.count
            return 0
        } catch {
            return -1
        }
    }
    return -1
}

@_cdecl("swift_mldsa87_verify")
public func swiftMLDsa87Verify(
    publicKey: UnsafeRawPointer,
    message: UnsafeRawPointer,
    messageLen: Int,
    signature: UnsafeRawPointer,
    signatureLen: Int
) -> Int32 {
    if #available(macOS 26, iOS 26, *) {
        do {
            let pubData = Data(bytes: publicKey, count: 2592)
            let key = try MLDSA87.PublicKey(rawRepresentation: pubData)
            let msgData = Data(bytes: message, count: messageLen)
            let sigData = Data(bytes: signature, count: signatureLen)

            return key.isValidSignature(sigData, for: msgData) ? 0 : 1
        } catch {
            return -1
        }
    }
    return -1
}

@_cdecl("swift_mldsa87_derive_public_key")
public func swiftMLDsa87DerivePublicKey(
    seed: UnsafeRawPointer, publicKey: UnsafeMutableRawPointer
) -> Int32 {
    if #available(macOS 26, iOS 26, *) {
        do {
            let seedData = Data(bytes: seed, count: 64)
            let key = try MLDSA87.PrivateKey(integrityCheckedRepresentation: seedData)
            let pubData = key.publicKey.rawRepresentation

            pubData.withUnsafeBytes { bytes in
                publicKey.copyMemory(from: bytes.baseAddress!, byteCount: bytes.count)
            }
            return 0
        } catch {
            return -1
        }
    }
    return -1
}

// MARK: - Secure Enclave ML-DSA65

@_cdecl("swift_se_mldsa65_generate_keypair")
public func swiftSEMLDsa65GenerateKeypair(
    dataRepresentation: UnsafeMutableRawPointer,
    dataRepresentationLen: UnsafeMutablePointer<Int>,
    publicKey: UnsafeMutableRawPointer
) -> Int32 {
    if #available(macOS 26, iOS 26, *) {
        do {
            let key = try SecureEnclave.MLDSA65.PrivateKey()
            let keyData = key.dataRepresentation
            let pubData = key.publicKey.rawRepresentation

            keyData.withUnsafeBytes { bytes in
                dataRepresentation.copyMemory(from: bytes.baseAddress!, byteCount: bytes.count)
            }
            dataRepresentationLen.pointee = keyData.count

            pubData.withUnsafeBytes { bytes in
                publicKey.copyMemory(from: bytes.baseAddress!, byteCount: bytes.count)
            }
            return 0
        } catch {
            return -1
        }
    }
    return -1
}

@_cdecl("swift_se_mldsa65_get_public_key")
public func swiftSEMLDsa65GetPublicKey(
    dataRepresentation: UnsafeRawPointer,
    dataRepresentationLen: Int,
    publicKey: UnsafeMutableRawPointer
) -> Int32 {
    if #available(macOS 26, iOS 26, *) {
        do {
            let keyData = Data(bytes: dataRepresentation, count: dataRepresentationLen)
            let key = try SecureEnclave.MLDSA65.PrivateKey(dataRepresentation: keyData)
            let pubData = key.publicKey.rawRepresentation

            pubData.withUnsafeBytes { bytes in
                publicKey.copyMemory(from: bytes.baseAddress!, byteCount: bytes.count)
            }
            return 0
        } catch {
            return -1
        }
    }
    return -1
}

@_cdecl("swift_se_mldsa65_sign")
public func swiftSEMLDsa65Sign(
    dataRepresentation: UnsafeRawPointer,
    dataRepresentationLen: Int,
    message: UnsafeRawPointer,
    messageLen: Int,
    signature: UnsafeMutableRawPointer,
    signatureLen: UnsafeMutablePointer<Int>
) -> Int32 {
    if #available(macOS 26, iOS 26, *) {
        do {
            let keyData = Data(bytes: dataRepresentation, count: dataRepresentationLen)
            let key = try SecureEnclave.MLDSA65.PrivateKey(dataRepresentation: keyData)
            let msgData = Data(bytes: message, count: messageLen)
            let sigData = try key.signature(for: msgData)

            sigData.withUnsafeBytes { bytes in
                signature.copyMemory(from: bytes.baseAddress!, byteCount: bytes.count)
            }
            signatureLen.pointee = sigData.count
            return 0
        } catch {
            return -1
        }
    }
    return -1
}

// MARK: - Secure Enclave ML-DSA87

@_cdecl("swift_se_mldsa87_generate_keypair")
public func swiftSEMLDsa87GenerateKeypair(
    dataRepresentation: UnsafeMutableRawPointer,
    dataRepresentationLen: UnsafeMutablePointer<Int>,
    publicKey: UnsafeMutableRawPointer
) -> Int32 {
    if #available(macOS 26, iOS 26, *) {
        do {
            let key = try SecureEnclave.MLDSA87.PrivateKey()
            let keyData = key.dataRepresentation
            let pubData = key.publicKey.rawRepresentation

            keyData.withUnsafeBytes { bytes in
                dataRepresentation.copyMemory(from: bytes.baseAddress!, byteCount: bytes.count)
            }
            dataRepresentationLen.pointee = keyData.count

            pubData.withUnsafeBytes { bytes in
                publicKey.copyMemory(from: bytes.baseAddress!, byteCount: bytes.count)
            }
            return 0
        } catch {
            return -1
        }
    }
    return -1
}

@_cdecl("swift_se_mldsa87_get_public_key")
public func swiftSEMLDsa87GetPublicKey(
    dataRepresentation: UnsafeRawPointer,
    dataRepresentationLen: Int,
    publicKey: UnsafeMutableRawPointer
) -> Int32 {
    if #available(macOS 26, iOS 26, *) {
        do {
            let keyData = Data(bytes: dataRepresentation, count: dataRepresentationLen)
            let key = try SecureEnclave.MLDSA87.PrivateKey(dataRepresentation: keyData)
            let pubData = key.publicKey.rawRepresentation

            pubData.withUnsafeBytes { bytes in
                publicKey.copyMemory(from: bytes.baseAddress!, byteCount: bytes.count)
            }
            return 0
        } catch {
            return -1
        }
    }
    return -1
}

@_cdecl("swift_se_mldsa87_sign")
public func swiftSEMLDsa87Sign(
    dataRepresentation: UnsafeRawPointer,
    dataRepresentationLen: Int,
    message: UnsafeRawPointer,
    messageLen: Int,
    signature: UnsafeMutableRawPointer,
    signatureLen: UnsafeMutablePointer<Int>
) -> Int32 {
    if #available(macOS 26, iOS 26, *) {
        do {
            let keyData = Data(bytes: dataRepresentation, count: dataRepresentationLen)
            let key = try SecureEnclave.MLDSA87.PrivateKey(dataRepresentation: keyData)
            let msgData = Data(bytes: message, count: messageLen)
            let sigData = try key.signature(for: msgData)

            sigData.withUnsafeBytes { bytes in
                signature.copyMemory(from: bytes.baseAddress!, byteCount: bytes.count)
            }
            signatureLen.pointee = sigData.count
            return 0
        } catch {
            return -1
        }
    }
    return -1
}
