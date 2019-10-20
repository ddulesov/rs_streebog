//! An implementation of the [Streebog][1] cryptographic hash function. It's
//! officially known as GOST R 34.11-2012.
//!
//! [1]: https://en.wikipedia.org/wiki/Streebog
//!
//! This implementation returns digest result using little-endian encoding
//! in the form of array with least significant octets first, thus compared to
//! specifications which uses big-endian result will have "reversed" order of
//! octets.
//!
//! # Usage
//!
//! An example of using `Streebog512` and `Streebog256` is:
//!
//! ```rust
//! use streebog::{Digest, Streebog256, Streebog512};
//!
//! // create a hasher object, to use it do not forget to import `Digest` trait
//! let mut hasher = Streebog256::new();
//! // write input message
//! hasher.input(b"input data");
//! // or process stream
//! // for input_data in stream {
//! //    hasher.input( input_data );
//! // }
//! // read hash digest (it will consume hasher)
//! let result = hasher.finish();
//!
//! // same for Streebog512
//! let mut hasher = Streebog512::new();
//! hasher.input(b"input data");
//! let result = hasher.finish();
//! ```

use std::{
    convert::From,
    default::Default,
    fmt,
    marker::PhantomData,
    mem::{transmute, MaybeUninit},
    ptr::{copy_nonoverlapping, write_bytes},
};

use crate::constant::{AX, BUFFER0, BUFFER512, CX};
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

#[repr(align(32))]
struct X512i {
    xmm: [__m256i; 2],
}

//#[cfg(target_feature = "avx2")]
impl X512i {
    #[inline(always)]
    unsafe fn store(&self, m: &mut B512) {
        let ptr = m.m256i.as_mut_ptr();
        _mm256_store_si256(ptr, self.xmm[0]);
        _mm256_store_si256(ptr.add(1), self.xmm[1]);
    }

    #[inline(always)]
    unsafe fn xor_r(&mut self, other: &X512i) {
        self.xmm[0] = _mm256_xor_si256(self.xmm[0], other.xmm[0]);
        self.xmm[1] = _mm256_xor_si256(self.xmm[1], other.xmm[1]);
    }

    #[inline(always)]
    unsafe fn into_xor_m(&self, other: &B512) -> B512 {
        self.into_xor_r(&X512i::from(other))
    }

    #[inline(always)]
    unsafe fn into_xor_r(&self, other: &X512i) -> B512 {
        let mut out: B512 = Default::default();
        let ptr: *mut __m256i = out.m256i.as_mut_ptr();

        let txmm1 = _mm256_xor_si256(self.xmm[0], other.xmm[0]);
        _mm256_store_si256(ptr, txmm1);

        let txmm2 = _mm256_xor_si256(self.xmm[1], other.xmm[1]);
        _mm256_store_si256(ptr.add(1), txmm2);
        out
    }
}

impl fmt::Debug for X512i {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        unsafe {
            for x in self.xmm.iter() {
                write!(
                    f,
                    "\n{:x} {:x}",
                    _mm256_extract_epi64(*x, 0),
                    _mm256_extract_epi64(*x, 1)
                )?
            }
            Ok(())
        }
    }
}

impl From<&B512> for X512i {
    fn from(b: &B512) -> Self {
        unsafe {
            let ptr = b.m256i.as_ptr();
            X512i {
                xmm: [_mm256_load_si256(ptr), _mm256_load_si256(ptr.add(1))],
            }
        }
    }
}

impl From<*const u8> for X512i {
    fn from(b: *const u8) -> Self {
        unsafe {
            let ptr = b as *const __m256i;
            X512i {
                xmm: [_mm256_loadu_si256(ptr), _mm256_loadu_si256(ptr.add(1))],
            }
        }
    }
}

pub trait DigestBlock {
    const INIT: u8;
    const SIZE: u8;
}

pub struct U256();
pub struct U512();

impl DigestBlock for U256 {
    const INIT: u8 = 0x01;
    const SIZE: u8 = 32;
}

impl DigestBlock for U512 {
    const INIT: u8 = 0x00;
    const SIZE: u8 = 64;
}

pub trait Digest {
    fn input(&mut self, data: &[u8]);
    fn finish(&mut self) -> Vec<u8>;
    fn result(&self) -> Vec<u8>;
    fn reset(&mut self);
    fn output_size(&self) -> usize;
}

#[repr(align(32))]
pub(crate) union B512 {
    pub b8: [u8; 64],
    pub b64: [u64; 8],
    pub b32: [u32; 16],
    pub m256i: [__m256i; 2],
}

impl B512 {
    fn new() -> B512 {
        B512 { b64: [0u64; 8] }
    }

    #[inline(always)]
    unsafe fn add(&mut self, other: &B512) {
        self.add_bytes(other.as_ptr())
    }

    #[inline(always)]
    unsafe fn add_bytes(&mut self, other: *const u8) {
        let mut c: u8 = 0;

        let other = std::slice::from_raw_parts(other as *const u64, 8).iter();
        for (v, o) in self.b64.iter_mut().zip(other) {
            c = _addcarryx_u64(c, *v, *o, v);
        }
    }

    #[inline(always)]
    unsafe fn as_ptr(&self) -> *const u8 {
        self.b8.as_ptr()
    }

    #[inline(always)]
    unsafe fn as_mut_ptr(&mut self) -> *mut u8 {
        self.b8.as_mut_ptr()
    }

    #[inline(always)]
    unsafe fn lps(self) -> X512i {
        let mut res = [_mm256_undefined_si256(); 2];

        for i in 0..2 {
            let mut x0: u64 = 0u64;
            let mut x1: u64 = 0u64;
            let mut x2: u64 = 0u64;
            let mut x3: u64 = 0u64;

            let i4 = i << 2;
            for j in 0..4 {
                let j3 = j << 3;
                let ax = AX.as_ptr().add(j << 8); //select AX page

                let idx = self.b8[i4 + (j3) + 0] as isize;
                x0 ^= *ax.offset(idx);

                let idx = self.b8[i4 + (j3) + 1] as isize;
                x1 ^= *ax.offset(idx);

                let idx = self.b8[i4 + (j3) + 2] as isize;
                x2 ^= *ax.offset(idx);

                let idx = self.b8[i4 + (j3) + 3] as isize;
                x3 ^= *ax.offset(idx);

                assert!(i4 + j3 + 3 < 32);
            }

            for j in 4..8 {
                let j3 = j << 3;
                let ax = AX.as_ptr().add(j << 8); //select AX page

                let idx = self.b8[i4 + (j3) + 0] as isize;
                x0 ^= *ax.offset(idx);

                let idx = self.b8[i4 + (j3) + 1] as isize;
                x1 ^= *ax.offset(idx);

                let idx = self.b8[i4 + (j3) + 2] as isize;
                x2 ^= *ax.offset(idx);

                let idx = self.b8[i4 + (j3) + 3] as isize;
                x3 ^= *ax.offset(idx);

                assert!(i4 + j3 >= 32);
            }

            res[i] = _mm256_set_epi64x(
                transmute::<u64, i64>(x3),
                transmute::<u64, i64>(x2),
                transmute::<u64, i64>(x1),
                transmute::<u64, i64>(x0),
            );
        }

        X512i { xmm: res }
    }

    #[inline(always)]
    unsafe fn g(&mut self, n: &B512, m: *const u8) {
        //self is h (hash buffer)
        let mut key: X512i = X512i::from(&*self).into_xor_m(n).lps();
        let mut buffer: X512i = X512i::from(m);

        for c in CX.iter() {
            buffer = buffer.into_xor_r(&key).lps();
            key = key.into_xor_m(c).lps();
        }

        key.xor_r(&buffer);
        key.xor_r(&X512i::from(m));
        key.xor_r(&X512i::from(&*self));

        key.store(self);
	_mm256_zeroupper();
    }
}

impl Clone for B512 {
    fn clone(&self) -> Self {
        unsafe {
            B512 {
                b64: self.b64.clone(),
            }
        }
    }
}

impl From<&[u8]> for B512 {
    fn from(data: &[u8]) -> Self {
        assert!(data.len() == 64);
        let mut b8: [u8; 64] = unsafe { MaybeUninit::uninit().assume_init() };
        unsafe {
            copy_nonoverlapping(data.as_ptr(), b8.as_mut_ptr(), 64);
        };
        B512 { b8: b8 }
    }
}

impl PartialEq for B512 {
    fn eq(&self, other: &Self) -> bool {
        unsafe { self.b64.iter().zip(other.b64.iter()).all(|(a, b)| a == b) }
    }
}

impl fmt::Debug for B512 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        unsafe { write!(f, "B512 {:?}", &self.b64[..]) }
    }
}

impl AsRef<[u8]> for B512 {
    fn as_ref(&self) -> &[u8] {
        unsafe { self.b8.as_ref() }
    }
}

impl Default for B512 {
    fn default() -> Self {
        B512 {
            b8: unsafe { MaybeUninit::uninit().assume_init() },
        }
    }
}

#[repr(align(32))]
//#[cfg(target_feature = "avx2")]
pub struct StreeBog<T: DigestBlock> {
    h: B512, //must be aligned on a 16-byte boundary
    buffer: B512,
    n: B512,
    sigma: B512,
    bufsize: usize,
    phantom: PhantomData<T>,
}

impl<T> fmt::Debug for StreeBog<T>
where
    T: DigestBlock,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "StreeBog{} buffer:{:?} hash:{:?}",
            T::SIZE,
            &self.buffer,
            &self.h
        )
    }
}

//#[cfg(target_feature = "avx2")]
impl<T> StreeBog<T>
where
    T: DigestBlock,
{
    pub fn new() -> StreeBog<T> {
        let mut o = StreeBog {
            h: Default::default(),
            buffer: Default::default(),
            n: Default::default(),
            sigma: Default::default(),
            bufsize: 0,
            phantom: PhantomData,
        }; //
        o.reset();
        o
    }

    #[inline(always)]
    unsafe fn pad(&mut self) {
        if self.bufsize < 64 {
            let l = 64 - self.bufsize;
            let ptr: *mut u8 = self.buffer.as_mut_ptr().add(self.bufsize); //  self.buffer.b8[self.bufsize..64].as_mut_ptr();

            write_bytes(ptr, 0, l);

            *ptr = 0x01;
        }
    }

    unsafe fn stage2(&mut self, data: *const u8) {
        self.h.g(&self.n, data);
        self.n.add(&BUFFER512);
        self.sigma.add_bytes(data);
	//_mm256_zeroupper();
    }

    unsafe fn stage3(&mut self) {
        let mut buf = B512::new();
        buf.b64[0] = (self.bufsize as u64) << 3;
        self.pad();

        self.h.g(&self.n, self.buffer.as_ptr());

        self.n.add(&buf);
        self.sigma.add(&self.buffer);

        self.h.g(&BUFFER0, self.n.as_ptr());
        self.h.g(&BUFFER0, self.sigma.as_ptr());
	//_mm256_zeroupper();
    }
}

impl<T> Digest for StreeBog<T>
where
    T: DigestBlock,
{
    fn input(&mut self, data: &[u8]) {
        let mut l: usize = data.len();

        unsafe {
            let buf_ptr = self.buffer.as_mut_ptr();
            let mut data_ptr = data.as_ptr();

            //add data in tail of rest buffer data
            if self.bufsize > 0 {
                let mut chunk = 64 - self.bufsize;
                if chunk > l {
                    chunk = l;
                }

                copy_nonoverlapping(data_ptr, buf_ptr.add(self.bufsize), chunk);
                self.bufsize += chunk;

                l -= chunk;

                data_ptr = data_ptr.add(chunk);

                if self.bufsize == 64 {
                    self.stage2(self.buffer.as_ptr());
                    self.bufsize = 0;
                }
            }
            //full block
            while l > 63 {
                //copy_nonoverlapping(data_ptr, buf_ptr, 64 );
                self.stage2(data_ptr);
                data_ptr = data_ptr.add(64);

                l -= 64;
            }
            //save tail
            if l > 0 {
                copy_nonoverlapping(data_ptr, buf_ptr, l);
                self.bufsize = l;
            } else {
                self.bufsize = 0;
            }
        }
    }

    fn result(&self) -> Vec<u8> {
        let h: &[u8] = self.h.as_ref();

        match T::SIZE {
            32 => h[32..64].into(),
            64 => h.into(),
            _ => unreachable!(),
        }
    }

    fn finish(&mut self) -> Vec<u8> {
        unsafe {
            self.stage3();
        };
        self.result()
    }

    fn reset(&mut self) {
        unsafe {
            write_bytes(self as *mut StreeBog<T>, 0, 1);
            write_bytes(self.h.as_mut_ptr(), T::INIT, 64);
        }
    }

    fn output_size(&self) -> usize {
        (T::SIZE as usize) << 3
    }
}
