use std::slice;
use std::os::raw::c_uchar;

#[no_mangle]
pub extern "C" fn encrypt_ige(
    input: *const c_uchar,
    input_len: usize,
    key: *const c_uchar,
    iv: *const c_uchar,
    output: *mut c_uchar
) {
    let input_slice = unsafe { slice::from_raw_parts(input, input_len) };
    
    // Convert key and iv to correct array types
    let mut key_array = [0u8; 32];
    let mut iv_array = [0u8; 32];
    
    unsafe {
        key_array.copy_from_slice(slice::from_raw_parts(key, 32));
        iv_array.copy_from_slice(slice::from_raw_parts(iv, 32));
    }

    let result = grammers_crypto::encrypt_ige(input_slice, &key_array, &iv_array);
    
    unsafe {
        std::ptr::copy_nonoverlapping(result.as_ptr(), output, result.len());
    }
}

#[no_mangle]
pub extern "C" fn decrypt_ige(
    input: *const c_uchar,
    input_len: usize,
    key: *const c_uchar,
    iv: *const c_uchar,
    output: *mut c_uchar
) {
    let input_slice = unsafe { slice::from_raw_parts(input, input_len) };
    
    // Convert key and iv to correct array types
    let mut key_array = [0u8; 32];
    let mut iv_array = [0u8; 32];
    
    unsafe {
        key_array.copy_from_slice(slice::from_raw_parts(key, 32));
        iv_array.copy_from_slice(slice::from_raw_parts(iv, 32));
    }

    let result = grammers_crypto::decrypt_ige(input_slice, &key_array, &iv_array);
    
    unsafe {
        std::ptr::copy_nonoverlapping(result.as_ptr(), output, result.len());
    }
}