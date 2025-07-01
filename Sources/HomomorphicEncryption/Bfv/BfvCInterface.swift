import Foundation

// Wrapper for a simple integer value, for demonstration
public class BfvValueWrapper {
    public var value: Int64
    public init(_ value: Int64) { self.value = value }
}

@_cdecl("bfv_create_value")
public func bfv_create_value(_ val: Int64) -> UnsafeMutableRawPointer {
    let wrapper = BfvValueWrapper(val)
    return UnsafeMutableRawPointer(Unmanaged.passRetained(wrapper).toOpaque())
}

@_cdecl("bfv_add_values")
public func bfv_add_values(_ lhsPtr: UnsafeMutableRawPointer, _ rhsPtr: UnsafeMutableRawPointer) -> Int64 {
    let lhs = Unmanaged<BfvValueWrapper>.fromOpaque(lhsPtr).takeUnretainedValue()
    let rhs = Unmanaged<BfvValueWrapper>.fromOpaque(rhsPtr).takeUnretainedValue()
    return lhs.value + rhs.value
}

@_cdecl("bfv_free_value")
public func bfv_free_value(_ ptr: UnsafeMutableRawPointer) {
    Unmanaged<BfvValueWrapper>.fromOpaque(ptr).release()
}