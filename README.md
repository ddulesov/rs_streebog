# rs_streebog
rust  [streebog](https://en.wikipedia.org/wiki/Streebog) hash SIMD accelerated implementation  
[![Build Status](https://travis-ci.com/ddulesov/rs_streebog.svg?branch=master)](https://travis-ci.com/ddulesov/rs_streebog)


## Requirements
x86_64 AVX2 capable CPU (Haswell or newer )
On Core i5 4210U (Haswell 1.7 GHz) give me 74MB/sec   

## Usage

```rust
extern crate hex;
extern crate streebog;

use streebog::{Streebog512, Digest };

fn hash_from_str(hexstr: &str) -> Vec<u8> {
    hex::decode(hexstr).unwrap()
}

fn main() {
    let input = b"012345678901234567890123456789012345678901234567890123456789012";

    let mut h512 = Streebog512::new();
    h512.input( input );

    let result = h512.finish();
    println!("result {:?}", result );
}
```

