
open Printf
open ExtLib

let (&) f x = f x
let (>>) x f = f x
let fail fmt = Printf.ksprintf failwith fmt

type ipv4 = int32

let bytes_of_ipv4 addr =
  let a = Int32.to_int & Int32.shift_right_logical (Int32.logand 0xFF000000l addr) 24 in
  let b = Int32.to_int & Int32.shift_right_logical (Int32.logand 0x00FF0000l addr) 16 in
  let c = Int32.to_int & Int32.shift_right_logical (Int32.logand 0x0000FF00l addr) 8 in
  let d = Int32.to_int & Int32.logand 0x000000FFl addr in
  (a,b,c,d)

let string_of_ipv4 addr =
  let (a,b,c,d) = bytes_of_ipv4 addr in
  sprintf "%u.%u.%u.%u" a b c d

let string_of_domain = String.concat "."
let domain_of_string s = String.nsplit s "."
let domain_equal d1 d2 =
  try
    List.for_all2 (fun n1 n2 -> String.uppercase n1 = String.uppercase n2) d1 d2
  with
  | Invalid_argument _ -> false
