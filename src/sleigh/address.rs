use super::types::Address;
use std::fmt;

// pub trait AddressIface {
//     fn as_int(&self) -> u64;
//     fn adding(&self, addend: u64) -> Address;
// }

// impl AddressIface for Address {
//     fn as_int(&self) -> u64 {
//         return self.offset;
//     }

//     fn adding(&self, addend: u64) -> Address {
//         return Address {
//             space: self.space.clone(),
//             offset: self.offset + addend
//         };
//     }
// }

impl Address {
    pub fn to_string(&self) -> String {
        format!("0x{:x}", self.offset)
    }

    // pub fn adding(&self, addend: u64) -> Address {
    //     return Address {
    //         space: self.space.clone(),
    //         offset: self.offset + addend
    //     };
    // }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}
