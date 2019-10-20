#![feature(test)]
mod constant;
mod streebog;

#[cfg(test)]
extern crate hex;

#[cfg(test)]
extern crate test;

pub use crate::streebog::{Digest, StreeBog, U256, U512};
pub type Streebog256 = StreeBog<U256>;
pub type Streebog512 = StreeBog<U512>;

#[cfg(test)]
mod tests {
    //use core::arch::x86_64::*;
    use super::test::Bencher;
    use crate::streebog::Digest;

    fn hash_from_str(hexstr: &str) -> Vec<u8> {
        hex::decode(hexstr).unwrap()
    }

    #[bench]
    fn streebog512(b: &mut Bencher) {
        let input = b"012345678901234567890123456789012345678901234567890123456789012";

        b.iter(|| {
            let mut h512 = crate::Streebog512::new();
            h512.input(input);

            let _result = h512.finish();
        });

        b.bytes = input.len() as u64;
    }

    #[bench]
    fn streebog256(b: &mut Bencher) {
        let input = b"012345678901234567890123456789012345678901234567890123456789012";

        b.iter(|| {
            let mut h256 = crate::Streebog256::new();
            h256.input(input);

            let _result = h256.finish();
        });

        b.bytes = input.len() as u64;
    }

    #[bench]
    fn streebog_long(b: &mut Bencher) {
	let mut input = [0u8; 8192];

	for i in 0..8192 {
	 	input[i] =  (i & 0xFF) as u8;
	}

        b.iter(|| {
            let mut h = crate::Streebog512::new();
            h.input(input.as_ref());

            let _result = h.finish();
        });

        b.bytes = input.len() as u64;
    }

    #[test]
    fn streebog_hash() {
        let input = b"012345678901234567890123456789012345678901234567890123456789012";

        let mut h = crate::Streebog512::new();
        h.input(input);
        let result = h.finish();

        let et = hash_from_str("1b54d01a4af5b9d5cc3d86d68d285462b19abc2475222f35c085122be4ba1ffa00ad30f8767b3a82384c6574f024c311e2a481332b08ef7f41797891c1646f48");
        assert_eq!(result, et);

        assert_eq!(h.output_size(), 512);

        let mut h = crate::Streebog256::new();
        h.input(input);
        let result = h.finish();

        let et = hash_from_str("9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500");
        assert_eq!(result, et);
        assert_eq!(h.output_size(), 256);

        println!("long data (other 64 bytes)");
        let input = br#"012345678901234567890123456789012345678901234567890123456789012
        00000000000000000000000000000000000000000000000000000000000000000000
        11111111111111111111111111111111111111111111111111111111111111111111
        22222222222222222222222222222222222222222222222222222222222222222222
        33333333333333333333333333333333333333333333333333333333333333333333
        44444444444444444444444444444444444444444444444444444444444444444444
        55555555555555555555555555555555555555555555555555555555555555555555
        66666666666666666666666666666666666666666666666666666666666666666666
        77777777777777777777777777777777777777777777777777777777777777777777
        88888888888888888888888888888888888888888888888888888888888888888888
        99999999999999999999999999999999999999999999999999999999999999999999
        00000000000000000000000000000000000000000000000000000000000000000000"#;

        let mut h = crate::Streebog512::new();
        h.input(input);
        let result = h.finish();

        let et = hash_from_str("f70070043d55409e21fb7a175100400e1c24c869d97b7191abddd9718f7b73217cbe481a33a607effaa3e50f9fc965ee9fffc3316325bfd2de3169019564f340");
        assert_eq!(result, et);
    }
}
