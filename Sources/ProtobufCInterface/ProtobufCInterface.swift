import Foundation
import HomomorphicEncryption
import HomomorphicEncryptionProtobuf

@_cdecl("bfv_serialize_ciphertext_to_protobuf")
public func bfv_serialize_ciphertext_to_protobuf(
    _ ctPtr: UnsafeMutableRawPointer?,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?
) -> Int {
    guard let ctPtr = ctPtr, let outBytes = outBytes else {
        setThreadSafeError("Null ciphertext pointer or outBytes")
        return 0
    }
    do {
        let ctWrapper = Unmanaged<BfvCiphertextWrapper>.fromOpaque(ctPtr).takeUnretainedValue()
        // Convert to protobuf message
        let proto = try ctWrapper.ciphertext.toProto()
        // Serialize to Data
        let data = try proto.serializedData()
        // Allocate C buffer
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: data.count)
        data.copyBytes(to: buffer, count: data.count)
        outBytes.pointee = buffer
        return data.count
    } catch {
        setThreadSafeError("Failed to serialize ciphertext: \(error)")
        return 0
    }
}

@_cdecl("bfv_deserialize_ciphertext_from_protobuf")
public func bfv_deserialize_ciphertext_from_protobuf(
    _ bytes: UnsafePointer<UInt8>?,
    _ len: Int
) -> UnsafeMutableRawPointer? {
    guard let bytes = bytes, len > 0 else {
        setThreadSafeError("Null bytes or zero length")
        return nil
    }
    do {
        let data = Data(bytes: bytes, count: len)
        // Parse protobuf message
        let proto = try Apple_Swift_Homomorphic_Encryption_V1_He_Ciphertext(serializedData: data)
        // Convert to Swift ciphertext
        let ciphertext = try Ciphertext<Bfv<UInt64>, Coeff>(fromProto: proto)
        let wrapper = BfvCiphertextWrapper(ciphertext: ciphertext)
        return UnsafeMutableRawPointer(Unmanaged.passRetained(wrapper).toOpaque())
    } catch {
        setThreadSafeError("Failed to deserialize ciphertext: \(error)")
        return nil
    }
}

@_cdecl("bfv_free_bytes")
public func bfv_free_bytes(_ bytes: UnsafeMutablePointer<UInt8>?) {
    if let bytes = bytes {
        bytes.deallocate()
    }
}