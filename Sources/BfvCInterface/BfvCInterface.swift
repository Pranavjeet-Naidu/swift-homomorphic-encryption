import Foundation
import ModularArithmetic
import HomomorphicEncryption

// MARK: - Wrapper Classes

/// Wrapper for encryption parameters
nonisolated public class BfvEncryptionParametersWrapper {
    nonisolated public var parameters: EncryptionParameters<UInt64>
    
    nonisolated public init(parameters: EncryptionParameters<UInt64>) {
        self.parameters = parameters
    }
}

/// Wrapper for context
nonisolated public class BfvContextWrapper {
    nonisolated public var context: Context<Bfv<UInt64>>
    
    nonisolated public init(context: Context<Bfv<UInt64>>) {
        self.context = context
    }
}

/// Wrapper for secret key
nonisolated public class BfvSecretKeyWrapper {
    nonisolated public var secretKey: SecretKey<Bfv<UInt64>>
    
    nonisolated public init(secretKey: SecretKey<Bfv<UInt64>>) {
        self.secretKey = secretKey
    }
}

/// Wrapper for plaintext
nonisolated public class BfvPlaintextWrapper {
    nonisolated public var plaintext: Plaintext<Bfv<UInt64>, Coeff>
    
    nonisolated public init(plaintext: Plaintext<Bfv<UInt64>, Coeff>) {
        self.plaintext = plaintext
    }
}

/// Wrapper for ciphertext
nonisolated public class BfvCiphertextWrapper {
    nonisolated public var ciphertext: Ciphertext<Bfv<UInt64>, Coeff>
    
    nonisolated public init(ciphertext: Ciphertext<Bfv<UInt64>, Coeff>) {
        self.ciphertext = ciphertext
    }
}

/// Wrapper for evaluation key
nonisolated public class BfvEvaluationKeyWrapper {
    nonisolated public var evaluationKey: EvaluationKey<Bfv<UInt64>>
    
    nonisolated public init(evaluationKey: EvaluationKey<Bfv<UInt64>>) {
        self.evaluationKey = evaluationKey
    }
}

// MARK: - Error Handling
nonisolated public actor ErrorHandlingActorType {}
// Define a custom global actor for our error handling
@globalActor nonisolated public struct ErrorHandlingActor: GlobalActor, Sendable {
    nonisolated public static let shared = ErrorHandlingActorType()
}

// Thread-safe error handling
private let errorLock = NSLock()

// Explicitly isolate to our custom actor to silence the warning
@preconcurrency
nonisolated(unsafe) public var threadSafeLastError: String = ""


nonisolated func setThreadSafeError(_ message: String) {
    errorLock.lock()
    defer { errorLock.unlock() }
    threadSafeLastError = message
}


@_cdecl("bfv_get_last_error")

nonisolated public func bfv_get_last_error() -> UnsafeMutablePointer<Int8>? {
    errorLock.lock()
    defer { errorLock.unlock() }
    return strdup(threadSafeLastError) as UnsafeMutablePointer<Int8>?
}

@_cdecl("bfv_free_string")
nonisolated public func bfv_free_string(_ ptr: UnsafeMutablePointer<Int8>?) {
    if let ptr = ptr {
        free(ptr)
    }
}

// MARK: - Parameter Creation

@_cdecl("bfv_create_parameters_from_preset")

nonisolated public func bfv_create_parameters_from_preset(_ preset: Int32) -> UnsafeMutableRawPointer? {
    do {
        let presetParameter: PredefinedRlweParameters
        
        switch preset {
        case 0:
            presetParameter = .n_8192_logq_28_60_60_logt_20
        case 1:
            presetParameter = .n_4096_logq_27_28_28_logt_5
        case 2:
            presetParameter = .n_8192_logq_3x55_logt_42
        default:
            setThreadSafeError("Invalid preset value")
            return nil
        }
        
        let params = try EncryptionParameters<UInt64>(from: presetParameter)
        let wrapper = BfvEncryptionParametersWrapper(parameters: params)
        return UnsafeMutableRawPointer(Unmanaged.passRetained(wrapper).toOpaque())
    } catch {
        setThreadSafeError("Failed to create parameters: \(error)")
        return nil
    }
}

@_cdecl("bfv_free_parameters")
nonisolated public func bfv_free_parameters(_ ptr: UnsafeMutableRawPointer?) {
    if let ptr = ptr {
        Unmanaged<BfvEncryptionParametersWrapper>.fromOpaque(ptr).release()
    }
}

// MARK: - Context Creation

@_cdecl("bfv_create_context")

nonisolated public func bfv_create_context(_ parametersPtr: UnsafeMutableRawPointer?) -> UnsafeMutableRawPointer? {
    guard let parametersPtr = parametersPtr else {
        setThreadSafeError("Null parameters pointer")
        return nil
    }
    
    do {
        let paramsWrapper = Unmanaged<BfvEncryptionParametersWrapper>.fromOpaque(parametersPtr).takeUnretainedValue()
        let context = try Context<Bfv<UInt64>>(encryptionParameters: paramsWrapper.parameters)
        let wrapper = BfvContextWrapper(context: context)
        return UnsafeMutableRawPointer(Unmanaged.passRetained(wrapper).toOpaque())
    } catch {
        setThreadSafeError("Failed to create context: \(error)")
        return nil
    }
}

@_cdecl("bfv_free_context")

nonisolated public func bfv_free_context(_ ptr: UnsafeMutableRawPointer?) {
    if let ptr = ptr {
        Unmanaged<BfvContextWrapper>.fromOpaque(ptr).release()
    }
}

// MARK: - Secret Key Generation

@_cdecl("bfv_generate_secret_key")

nonisolated public func bfv_generate_secret_key(_ contextPtr: UnsafeMutableRawPointer?) -> UnsafeMutableRawPointer? {
    guard let contextPtr = contextPtr else {
        setThreadSafeError("Null context pointer")
        return nil
    }
    
    do {
        let contextWrapper = Unmanaged<BfvContextWrapper>.fromOpaque(contextPtr).takeUnretainedValue()
        let secretKey = try contextWrapper.context.generateSecretKey()
        let wrapper = BfvSecretKeyWrapper(secretKey: secretKey)
        return UnsafeMutableRawPointer(Unmanaged.passRetained(wrapper).toOpaque())
    } catch {
        setThreadSafeError("Failed to generate secret key: \(error)")
        return nil
    }
}

@_cdecl("bfv_free_secret_key")
nonisolated public func bfv_free_secret_key(_ ptr: UnsafeMutableRawPointer?) {
    if let ptr = ptr {
        Unmanaged<BfvSecretKeyWrapper>.fromOpaque(ptr).release()
    }
}

// MARK: - Evaluation Key Generation

@_cdecl("bfv_generate_evaluation_key")

nonisolated public func bfv_generate_evaluation_key(_ contextPtr: UnsafeMutableRawPointer?, _ secretKeyPtr: UnsafeMutableRawPointer?) -> UnsafeMutableRawPointer? {
    guard let contextPtr = contextPtr, let secretKeyPtr = secretKeyPtr else {
        setThreadSafeError("Null context or secret key pointer")
        return nil
    }
    
    do {
        let contextWrapper = Unmanaged<BfvContextWrapper>.fromOpaque(contextPtr).takeUnretainedValue()
        let secretKeyWrapper = Unmanaged<BfvSecretKeyWrapper>.fromOpaque(secretKeyPtr).takeUnretainedValue()
        
        let config = EvaluationKeyConfig(
            galoisElements: [3, 5, 7], // Common Galois elements for rotation
            hasRelinearizationKey: true
        )
        
        let evalKey = try Bfv<UInt64>.generateEvaluationKey(
            context: contextWrapper.context,
            config: config,
            using: secretKeyWrapper.secretKey
        )
        
        let wrapper = BfvEvaluationKeyWrapper(evaluationKey: evalKey)
        return UnsafeMutableRawPointer(Unmanaged.passRetained(wrapper).toOpaque())
    } catch {
        setThreadSafeError("Failed to generate evaluation key: \(error)")
        return nil
    }
}

@_cdecl("bfv_free_evaluation_key")
nonisolated public func bfv_free_evaluation_key(_ ptr: UnsafeMutableRawPointer?) {
    if let ptr = ptr {
        Unmanaged<BfvEvaluationKeyWrapper>.fromOpaque(ptr).release()
    }
}

// MARK: - Encoding and Encryption

@_cdecl("bfv_encode_int_array")
nonisolated public func bfv_encode_int_array(_ contextPtr: UnsafeMutableRawPointer?, _ values: UnsafePointer<Int64>?, _ count: Int32) -> UnsafeMutableRawPointer? {
    // Debug logging
    print("bfv_encode_int_array called with context: \(String(describing: contextPtr)), values: \(String(describing: values)), count: \(count)")
    
    guard let contextPtr = contextPtr, let values = values else {
        setThreadSafeError("Null context pointer or values array")
        return nil
    }
    
    do {
        let contextWrapper = Unmanaged<BfvContextWrapper>.fromOpaque(contextPtr).takeUnretainedValue()
        print("Context unwrapped successfully")
        
        let valuesArray = Array(UnsafeBufferPointer(start: values, count: Int(count))).map { UInt64($0) }
        print("Values array converted: \(valuesArray)")
        
        // Explicitly verify the context is valid before encoding
        print("Polynomial modulus degree: \(contextWrapper.context.encryptionParameters.polyDegree)")
        
        let plaintext: Plaintext<Bfv<UInt64>, Coeff> = try contextWrapper.context.encode(
            values: valuesArray,
            format: .coefficient
        )
        print("Encoding successful")
        
        let wrapper = BfvPlaintextWrapper(plaintext: plaintext)
        return UnsafeMutableRawPointer(Unmanaged.passRetained(wrapper).toOpaque())
    } catch {
        setThreadSafeError("Failed to encode values: \(error)")
        print("Encoding error: \(error)")
        return nil
    }
}

@_cdecl("bfv_free_plaintext")
nonisolated public func bfv_free_plaintext(_ ptr: UnsafeMutableRawPointer?) {
    if let ptr = ptr {
        Unmanaged<BfvPlaintextWrapper>.fromOpaque(ptr).release()
    }
}

@_cdecl("bfv_encrypt")

nonisolated public func bfv_encrypt(_ plaintextPtr: UnsafeMutableRawPointer?, _ secretKeyPtr: UnsafeMutableRawPointer?) -> UnsafeMutableRawPointer? {
    guard let plaintextPtr = plaintextPtr, let secretKeyPtr = secretKeyPtr else {
        setThreadSafeError("Null plaintext or secret key pointer")
        return nil
    }
    
    do {
        let plaintextWrapper = Unmanaged<BfvPlaintextWrapper>.fromOpaque(plaintextPtr).takeUnretainedValue()
        let secretKeyWrapper = Unmanaged<BfvSecretKeyWrapper>.fromOpaque(secretKeyPtr).takeUnretainedValue()
        
        let ciphertext = try plaintextWrapper.plaintext.encrypt(using: secretKeyWrapper.secretKey)
        
        let wrapper = BfvCiphertextWrapper(ciphertext: ciphertext)
        return UnsafeMutableRawPointer(Unmanaged.passRetained(wrapper).toOpaque())
    } catch {
        setThreadSafeError("Failed to encrypt: \(error)")
        return nil
    }
}

@_cdecl("bfv_free_ciphertext")
nonisolated public func bfv_free_ciphertext(_ ptr: UnsafeMutableRawPointer?) {
    if let ptr = ptr {
        Unmanaged<BfvCiphertextWrapper>.fromOpaque(ptr).release()
    }
}

// MARK: - Decryption and Decoding

@_cdecl("bfv_decrypt")

nonisolated public func bfv_decrypt(_ ciphertextPtr: UnsafeMutableRawPointer?, _ secretKeyPtr: UnsafeMutableRawPointer?) -> UnsafeMutableRawPointer? {
    guard let ciphertextPtr = ciphertextPtr, let secretKeyPtr = secretKeyPtr else {
        setThreadSafeError("Null ciphertext or secret key pointer")
        return nil
    }
    
    do {
        let ciphertextWrapper = Unmanaged<BfvCiphertextWrapper>.fromOpaque(ciphertextPtr).takeUnretainedValue()
        let secretKeyWrapper = Unmanaged<BfvSecretKeyWrapper>.fromOpaque(secretKeyPtr).takeUnretainedValue()
        
        let plaintext = try ciphertextWrapper.ciphertext.decrypt(using: secretKeyWrapper.secretKey)
        
        let wrapper = BfvPlaintextWrapper(plaintext: plaintext)
        return UnsafeMutableRawPointer(Unmanaged.passRetained(wrapper).toOpaque())
    } catch {
        setThreadSafeError("Failed to decrypt: \(error)")
        return nil
    }
}

@_cdecl("bfv_decode_to_int_array")

nonisolated public func bfv_decode_to_int_array(_ plaintextPtr: UnsafeMutableRawPointer?, _ resultArray: UnsafeMutablePointer<Int64>?, _ maxCount: Int32, _ actualCount: UnsafeMutablePointer<Int32>?) -> Bool {
    guard let plaintextPtr = plaintextPtr, let resultArray = resultArray, let actualCount = actualCount else {
        setThreadSafeError("Null plaintext pointer or result array")
        return false
    }
    
    do {
        let plaintextWrapper = Unmanaged<BfvPlaintextWrapper>.fromOpaque(plaintextPtr).takeUnretainedValue()
        let decodedValues: [UInt64] = try plaintextWrapper.plaintext.decode(format: .coefficient)
        
        let count = min(Int(maxCount), decodedValues.count)
        for i in 0..<count {
            resultArray[i] = Int64(decodedValues[i])
        }
        
        actualCount.pointee = Int32(count)
        return true
    } catch {
        setThreadSafeError("Failed to decode plaintext: \(error)")
        return false
    }
}

// MARK: - Homomorphic Operations

@_cdecl("bfv_add")

nonisolated public func bfv_add(_ lhsPtr: UnsafeMutableRawPointer?, _ rhsPtr: UnsafeMutableRawPointer?) -> UnsafeMutableRawPointer? {
    guard let lhsPtr = lhsPtr, let rhsPtr = rhsPtr else {
        setThreadSafeError("Null ciphertext pointer(s)")
        return nil
    }
    
    do {
        let lhsWrapper = Unmanaged<BfvCiphertextWrapper>.fromOpaque(lhsPtr).takeUnretainedValue()
        let rhsWrapper = Unmanaged<BfvCiphertextWrapper>.fromOpaque(rhsPtr).takeUnretainedValue()
        
        var result = lhsWrapper.ciphertext
        try result += rhsWrapper.ciphertext
        
        let wrapper = BfvCiphertextWrapper(ciphertext: result)
        return UnsafeMutableRawPointer(Unmanaged.passRetained(wrapper).toOpaque())
    } catch {
        setThreadSafeError("Failed to add ciphertexts: \(error)")
        return nil
    }
}

@_cdecl("bfv_sub")

nonisolated public func bfv_sub(_ lhsPtr: UnsafeMutableRawPointer?, _ rhsPtr: UnsafeMutableRawPointer?) -> UnsafeMutableRawPointer? {
    guard let lhsPtr = lhsPtr, let rhsPtr = rhsPtr else {
        setThreadSafeError("Null ciphertext pointer(s)")
        return nil
    }
    
    do {
        let lhsWrapper = Unmanaged<BfvCiphertextWrapper>.fromOpaque(lhsPtr).takeUnretainedValue()
        let rhsWrapper = Unmanaged<BfvCiphertextWrapper>.fromOpaque(rhsPtr).takeUnretainedValue()
        
        var result = lhsWrapper.ciphertext
        try result -= rhsWrapper.ciphertext
        
        let wrapper = BfvCiphertextWrapper(ciphertext: result)
        return UnsafeMutableRawPointer(Unmanaged.passRetained(wrapper).toOpaque())
    } catch {
        setThreadSafeError("Failed to subtract ciphertexts: \(error)")
        return nil
    }
}

@_cdecl("bfv_multiply")

nonisolated public func bfv_multiply(_ lhsPtr: UnsafeMutableRawPointer?, _ rhsPtr: UnsafeMutableRawPointer?, _ evalKeyPtr: UnsafeMutableRawPointer?) -> UnsafeMutableRawPointer? {
    guard let lhsPtr = lhsPtr, let rhsPtr = rhsPtr, let evalKeyPtr = evalKeyPtr else {
        setThreadSafeError("Null ciphertext or evaluation key pointer(s)")
        return nil
    }
    
    do {
        let lhsWrapper = Unmanaged<BfvCiphertextWrapper>.fromOpaque(lhsPtr).takeUnretainedValue()
        let rhsWrapper = Unmanaged<BfvCiphertextWrapper>.fromOpaque(rhsPtr).takeUnretainedValue()
        let evalKeyWrapper = Unmanaged<BfvEvaluationKeyWrapper>.fromOpaque(evalKeyPtr).takeUnretainedValue()
        
        // Multiply the ciphertexts in the coefficient domain
        let resultEval = try Bfv<UInt64>.multiplyWithoutScaling(lhsWrapper.ciphertext, rhsWrapper.ciphertext)
        // Convert back to coefficient domain and drop the extended base
        var resultCoeff = try Bfv<UInt64>.dropExtendedBase(from: resultEval)
        // Relinearize to reduce ciphertext size
        try Bfv<UInt64>.relinearize(&resultCoeff, using: evalKeyWrapper.evaluationKey)

        let wrapper = BfvCiphertextWrapper(ciphertext: resultCoeff)
        return UnsafeMutableRawPointer(Unmanaged.passRetained(wrapper).toOpaque())
    } catch {
        setThreadSafeError("Failed to multiply ciphertexts: \(error)")
        return nil
    }
}

@_cdecl("bfv_sub_plaintext")

nonisolated public func bfv_sub_plaintext(_ ciphertextPtr: UnsafeMutableRawPointer?, _ plaintextPtr: UnsafeMutableRawPointer?) -> UnsafeMutableRawPointer? {
    guard let ciphertextPtr = ciphertextPtr, let plaintextPtr = plaintextPtr else {
        setThreadSafeError("Null ciphertext or plaintext pointer")
        return nil
    }
    
    do {
        let ciphertextWrapper = Unmanaged<BfvCiphertextWrapper>.fromOpaque(ciphertextPtr).takeUnretainedValue()
        let plaintextWrapper = Unmanaged<BfvPlaintextWrapper>.fromOpaque(plaintextPtr).takeUnretainedValue()
        
        var result = ciphertextWrapper.ciphertext
        try result -= plaintextWrapper.plaintext
        
        let wrapper = BfvCiphertextWrapper(ciphertext: result)
        return UnsafeMutableRawPointer(Unmanaged.passRetained(wrapper).toOpaque())
    } catch {
        setThreadSafeError("Failed to subtract plaintext from ciphertext: \(error)")
        return nil
    }
}

@_cdecl("bfv_negate")

nonisolated public func bfv_negate(_ ciphertextPtr: UnsafeMutableRawPointer?) -> UnsafeMutableRawPointer? {
    guard let ciphertextPtr = ciphertextPtr else {
        setThreadSafeError("Null ciphertext pointer")
        return nil
    }
    
    let ciphertextWrapper = Unmanaged<BfvCiphertextWrapper>.fromOpaque(ciphertextPtr).takeUnretainedValue()
    var result = ciphertextWrapper.ciphertext
    Bfv<UInt64>.negAssignCoeff(&result)
    let wrapper = BfvCiphertextWrapper(ciphertext: result)
    return UnsafeMutableRawPointer(Unmanaged.passRetained(wrapper).toOpaque())
}

@_cdecl("bfv_add_plaintext")

nonisolated public func bfv_add_plaintext(_ ciphertextPtr: UnsafeMutableRawPointer?, _ plaintextPtr: UnsafeMutableRawPointer?) -> UnsafeMutableRawPointer? {
    guard let ciphertextPtr = ciphertextPtr, let plaintextPtr = plaintextPtr else {
        setThreadSafeError("Null ciphertext or plaintext pointer")
        return nil
    }
    
    do {
        let ciphertextWrapper = Unmanaged<BfvCiphertextWrapper>.fromOpaque(ciphertextPtr).takeUnretainedValue()
        let plaintextWrapper = Unmanaged<BfvPlaintextWrapper>.fromOpaque(plaintextPtr).takeUnretainedValue()
        
        var result = ciphertextWrapper.ciphertext
        try result += plaintextWrapper.plaintext
        
        let wrapper = BfvCiphertextWrapper(ciphertext: result)
        return UnsafeMutableRawPointer(Unmanaged.passRetained(wrapper).toOpaque())
    } catch {
        setThreadSafeError("Failed to add plaintext to ciphertext: \(error)")
        return nil
    }
}

// MARK: - Utility Functions

@_cdecl("bfv_get_noise_budget")

nonisolated public func bfv_get_noise_budget(_ ciphertextPtr: UnsafeMutableRawPointer?, _ secretKeyPtr: UnsafeMutableRawPointer?) -> Double {
    guard let ciphertextPtr = ciphertextPtr, let secretKeyPtr = secretKeyPtr else {
        setThreadSafeError("Null ciphertext or secret key pointer")
        return -1
    }
    
    do {
        let ciphertextWrapper = Unmanaged<BfvCiphertextWrapper>.fromOpaque(ciphertextPtr).takeUnretainedValue()
        let secretKeyWrapper = Unmanaged<BfvSecretKeyWrapper>.fromOpaque(secretKeyPtr).takeUnretainedValue()
        
        return try ciphertextWrapper.ciphertext.noiseBudget(using: secretKeyWrapper.secretKey, variableTime: false)
    } catch {
        setThreadSafeError("Failed to compute noise budget: \(error)")
        return -1
    }
}