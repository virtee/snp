// SPDX-License-Identifier: Apache-2.0

//! Helpful primitives for developing the crate.

/// Returns a string formatted into 16-bytes wide similar to the output of the
/// command-line tool hexdump.
///
/// * `bytes` - A slice of bytes to be formatted.
pub(crate) fn hexdump(bytes: &[u8]) -> String {
    let mut retval: String = String::new();
    for (i, byte) in bytes.iter().enumerate() {
        if (i % 16) == 0 {
            retval.push('\n');
        }
        retval.push_str(&format!("{byte:02x} "));
    }
    retval.push('\n');
    retval
}

#[cfg(test)]
mod test {

    mod hexdump_tests {
        use crate::util::hexdump;

        const RESULT: &str = "\n\
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \n\
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \n\
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \n\
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \n\
        00 00 00 00 00 00 00 00 \n";

        #[test]
        fn hexdump_array() {
            let some_data: [u8; 72] = [0u8; 72];
            assert_eq!(RESULT, hexdump(&some_data));
        }

        #[test]
        fn hexdump_vec() {
            let some_data: Vec<u8> = vec![0u8; 72];
            assert_eq!(RESULT, hexdump(some_data.as_slice()));
        }
    }
}
