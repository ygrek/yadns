(** Very incomplete *)

open Printf
open ExtLib

open Dns_utils
open Dns_format

(* FIXME global vars *)

(* replies with REFUSED *)
let cnt_refused = ref 0
(* not QUERY opcodes *)
let cnt_opcode = ref 0
(* bad packets *)
let cnt_error = ref 0

(*
module CC = Cache.Count
let cnt_qtype = CC.create ()
let qtypes () = CC.show cnt_qtype string_of_qtype
*)

let answer_query resolve qtype domain =
  match resolve domain with
  | None -> 
    incr cnt_refused;
    refused "couldn't resolve %s" (string_of_domain domain)
  | Some d ->
(*     CC.add cnt_qtype qtype; *)
    match qtype with
    | CNAME | SOA -> [make_rr_soa d],[],[]
    | NS -> 
      if domain_equal domain (domain_of_string d.name) then
        List.map (make_rr_ns domain) d.ns (* check for empty? *) , [], []
      else (* subdomain *)
        [],[make_rr_soa d],[]
      (*List.map (fun (name,ip) -> make_rr_a name ip) nameservers*)
    | A -> [make_rr_a domain d.ip],[],[]
    | _ -> notimpl "QTYPE %s" (string_of_qtype qtype)

let make_reply_exn (query:pkt) answer ~on_error k =
  let (id, qr, opc, rest) = get_dns_header query in
  match qr with
  | true -> failwith "response bit set"
  | false ->
    let question = ref [] in
    try
      match opc with
      | 0 -> (* QUERY *)
         let (qtype,domain,qn) = just_get_question rest in
         question := [qn];
         let f reply = k & make_reply_packet OK id opc !question reply in
         answer qtype domain f
      | n -> incr cnt_opcode; notimpl "opcode %d" n
    with
    | exn ->
      let rcode = on_error exn in
      k & make_reply_packet rcode id opc !question ([],[],[])

(*
let make_reply (query:pkt) answer =
  try
    make_reply_exn query answer (fun x -> Some x)
  with
  | exn -> 
    incr cnt_error; 
    log #error "DNS error: %s" (Exn.str exn); 
    None

let make_reply_s query answer =
  try
    make_reply_exn (to_pkt query) answer (fun p -> Some (of_pkt p))
  with
  | exn -> 
    incr cnt_error; 
    log #error "DNS error: %s" (Exn.str exn); 
    None
*)
