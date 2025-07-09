import Foundation
import HomomorphicEncryption
import HomomorphicEncryptionProtobuf
import BfvCInterface

// Error handling fallback if not imported
#if canImport(BfvCInterface)
// Use setThreadSafeError from BfvCInterface
#else
@_cdecl("setThreadSafeError")
public func setThreadSafeError(_ message: UnsafePointer<CChar>?) {}
#endif


import Foundation
import HomomorphicEncryption
import HomomorphicEncryptionProtobuf
import BfvCInterface

// Remove the fallback since we're importing BfvCInterface
// The setThreadSafeError function is already available from BfvCInterface

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
        let proto = try ctWrapper.ciphertext.serialize().proto()
        let data = try proto.serializedData()
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
    _ len: Int,
    _ ctxPtr: UnsafeMutableRawPointer?
) -> UnsafeMutableRawPointer? {
    print("DEBUG: Starting ciphertext deserialization")
    print("DEBUG: bytes pointer: \(String(describing: bytes))")
    print("DEBUG: len: \(len)")
    print("DEBUG: ctxPtr: \(String(describing: ctxPtr))")
    
    guard let bytes = bytes, len > 0, let ctxPtr = ctxPtr else {
        let error = "Null bytes, zero length, or null context"
        print("DEBUG: Guard failed: \(error)")
        setThreadSafeError(error)
        return nil
    }
    
    do {
        print("DEBUG: Unwrapping context wrapper")
        let ctxWrapper = Unmanaged<BfvContextWrapper>.fromOpaque(ctxPtr).takeUnretainedValue()
        let context = ctxWrapper.context
        print("DEBUG: Context unwrapped successfully")
        
        print("DEBUG: Creating Data from bytes")
        let data = Data(bytes: bytes, count: len)
        print("DEBUG: Data created, size: \(data.count)")
        
        print("DEBUG: Deserializing protobuf")
        let proto = try Apple_SwiftHomomorphicEncryption_V1_SerializedCiphertext(serializedBytes: data)
        print("DEBUG: Protobuf deserialized successfully")
        
        print("DEBUG: Converting to native format")
        let serialized: SerializedCiphertext<UInt64> = try proto.native()
        print("DEBUG: Native conversion successful")
        
        // Key fix: Try deserialization without specifying moduliCount first
        // The library should handle this automatically
        
        print("DEBUG: Attempting deserialization without explicit moduli count")
        
        // First try: let the library determine the moduli count automatically
        do {
            let ciphertext = try Ciphertext<Bfv<UInt64>, Coeff>(
                deserialize: serialized,
                context: context
                // moduliCount is optional and defaults to context.ciphertextContext.moduli.count
            )
            print("DEBUG: Successfully deserialized without explicit moduli count")
            let wrapper = BfvCiphertextWrapper(ciphertext: ciphertext)
            print("DEBUG: Wrapper created, returning pointer")
            return UnsafeMutableRawPointer(Unmanaged.passRetained(wrapper).toOpaque())
        } catch {
            print("DEBUG: Auto-detection failed: \(error)")
        }
        
        // Second try: manually determine the correct moduli count
        let contextModuliCount = context.encryptionParameters.coefficientModuli.count
        print("DEBUG: Context total moduli count: \(contextModuliCount)")
        
        // Try different moduli counts starting from the full count down to 1
        for tryModuliCount in stride(from: contextModuliCount, through: 1, by: -1) {
            do {
                print("DEBUG: Trying moduli count: \(tryModuliCount)")
                let ciphertext = try Ciphertext<Bfv<UInt64>, Coeff>(
                    deserialize: serialized,
                    context: context,
                    moduliCount: tryModuliCount
                )
                print("DEBUG: Successfully deserialized with moduli count: \(tryModuliCount)")
                let wrapper = BfvCiphertextWrapper(ciphertext: ciphertext)
                print("DEBUG: Wrapper created, returning pointer")
                return UnsafeMutableRawPointer(Unmanaged.passRetained(wrapper).toOpaque())
            } catch {
                print("DEBUG: Failed with moduli count \(tryModuliCount): \(error)")
                continue
            }
        }
        
        // If we reach here, all attempts failed
        let errorMsg = "All moduli count attempts failed"
        print("DEBUG: \(errorMsg)")
        setThreadSafeError(errorMsg)
        return nil
    } catch {
        let errorMsg = "Failed to deserialize ciphertext: \(error)"
        print("DEBUG: Exception caught: \(errorMsg)")
        setThreadSafeError(errorMsg)
        return nil
    }
}

@_cdecl("bfv_serialize_plaintext_to_protobuf")
public func bfv_serialize_plaintext_to_protobuf(
    _ ptPtr: UnsafeMutableRawPointer?,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?
) -> Int {
    guard let ptPtr = ptPtr, let outBytes = outBytes else {
        setThreadSafeError("Null plaintext pointer or outBytes")
        return 0
    }
    do {
        let ptWrapper = Unmanaged<BfvPlaintextWrapper>.fromOpaque(ptPtr).takeUnretainedValue()
        let proto = ptWrapper.plaintext.serialize().proto()
        let data = try proto.serializedData()
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: data.count)
        data.copyBytes(to: buffer, count: data.count)
        outBytes.pointee = buffer
        return data.count
    } catch {
        setThreadSafeError("Failed to serialize plaintext: \(error)")
        return 0
    }
}

@_cdecl("bfv_deserialize_plaintext_from_protobuf")
public func bfv_deserialize_plaintext_from_protobuf(
    _ bytes: UnsafePointer<UInt8>?,
    _ len: Int,
    _ ctxPtr: UnsafeMutableRawPointer?
) -> UnsafeMutableRawPointer? {
    guard let bytes = bytes, len > 0, let ctxPtr = ctxPtr else {
        setThreadSafeError("Null bytes, zero length, or null context")
        return nil
    }
    do {
        let ctxWrapper = Unmanaged<BfvContextWrapper>.fromOpaque(ctxPtr).takeUnretainedValue()
        let context = ctxWrapper.context
        let data = Data(bytes: bytes, count: len)
        let proto = try Apple_SwiftHomomorphicEncryption_V1_SerializedPlaintext(serializedBytes: data)
        let serialized = proto.native()
        let plaintext = try Plaintext<Bfv<UInt64>, Coeff>(
            deserialize: serialized,
            context: context
        )
        let wrapper = BfvPlaintextWrapper(plaintext: plaintext)
        return UnsafeMutableRawPointer(Unmanaged.passRetained(wrapper).toOpaque())
    } catch {
        setThreadSafeError("Failed to deserialize plaintext: \(error)")
        return nil
    }
}

@_cdecl("bfv_free_bytes")
public func bfv_free_bytes(_ bytes: UnsafeMutablePointer<UInt8>?) {
    if let bytes = bytes {
        bytes.deallocate()
    }
}