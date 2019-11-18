extern crate ethereum_types;
extern crate core;
use ethereum_types::{Address,H160};
use std::str::FromStr;

fn main(){
   let ddd :u64 = 6443007314641091117;

   let address = "eFae41889479011037d834bE596A2904226cfA2D";
   let sss = H160::from_str(address).expect("ddd");
   println!("{:?}",sss);
   let sas = sss.low_u64();
   println!("{:?}",sas);
   let pre =H160::from(sas);
   println!("{:?}",pre);
}