(** RFC 1035 *)

module StdBuffer = Buffer

open Printf

open Bitstring
open ExtLib

open Dns_utils

type record = { id : int; name : string; ip : ipv4; ns : string list }

(* 4.1.1. Header section format *)

(* 
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*)

type pkt = bitstring

let to_pkt = bitstring_of_string
let of_pkt = string_of_bitstring

let bitmatch rest = { rest : -1 : bitstring }

let domain_name input =
  let rec labels bstr acc =
    bitmatch bstr with
    | { 0:8; :rest } -> Some (rest, List.rev acc)
    | { 0:2; len:6; label : 8*len : string; :rest } -> labels rest (label::acc)
    | { 0b11:2; ofs:16-2; :rest } -> (* pointer *)
        let (raw,_,_) = bstr in (* relies on full message bitstring *)
        begin match labels (dropbits (ofs*8) (to_pkt raw)) acc with
        | Some (_,answer) -> Some (rest,answer)
        | None -> None
        end
    | { } -> None
  in
   labels input []

let labels_of_domain domain =
  let open StdBuffer in
  let b = create 100 in
  List.iter (fun label -> 
    let len = min (String.length label) 63 in
    add_char b (Char.chr len);
    add_substring b label 0 len) domain;
  add_char b '\x00';
  contents b

let bitmatch dns_header =
    { id : 16;
      qr : 1; opc : 4; aa : 1; tc : 1; rd : 1; ra : 1; z : 3; rcode : 4;
      qdcount : 16; (** question *)
      ancount : 16; (** answer *)
      arcount : 16; (** authority *)
      adcount : 16  (** additional *)
    }

type rcode = OK | FMTERROR | SERVFAIL | NXDOMAIN | NOTIMPL | REFUSED

exception Error of rcode * string
let err rcode fmt = ksprintf (fun str -> raise (Error (rcode,str))) fmt
let notimpl fmt = err NOTIMPL fmt
let fmterror fmt = err FMTERROR fmt
let servfail fmt = err SERVFAIL fmt
let refused fmt = err REFUSED fmt
let nxdomain fmt = err NXDOMAIN fmt

(** 3.2.2. TYPE values *)

type qtype = A | NS | CNAME | SOA | MX | TXT | AAAA | A6 | PTR | SRV
let int_of_qtype = function
  | A -> 1
  | NS -> 2
  | CNAME -> 5
  | SOA -> 6
  | PTR -> 12
  | MX -> 15
  | TXT -> 16
  | AAAA -> 28 (* RFC 1886 *)
  | SRV -> 33  (* RFC 2782 *)
  | A6 -> 38 (* RFC 2874 *)
let qtype_of_int = function
  | 1 -> A
  | 2 -> NS
  | 5 -> CNAME
  | 6 -> SOA
  | 12 -> PTR
  | 15 -> MX
  | 16 -> TXT
  | 28 -> AAAA
  | 33 -> SRV
  | 38 -> A6
  | x -> notimpl "TYPE %u" x
let string_of_qtype = function
  | A -> "A"
  | NS -> "NS"
  | CNAME -> "CNAME"
  | SOA -> "SOA"
  | PTR -> "PTR"
  | MX -> "MX"
  | TXT -> "TXT"
  | AAAA -> "AAAA"
  | SRV -> "SRV"
  | A6 -> "A6"

let int_of_rcode = function
  | OK       -> 0
  | FMTERROR -> 1
  | SERVFAIL -> 2
  | NXDOMAIN -> 3
  | NOTIMPL  -> 4
  | REFUSED  -> 5
let string_of_rcode = function
  | OK -> "OK"
  | FMTERROR -> "FMTERROR"
  | SERVFAIL -> "SERVFAIL"
  | NXDOMAIN -> "NXDOMAIN"
  | NOTIMPL -> "NOTIMPL"
  | REFUSED -> "REFUSED"
let rcode_of_int = function
  | 0 -> OK
  | 1 -> FMTERROR
  | 2 -> SERVFAIL
  | 3 -> NXDOMAIN
  | 4 -> NOTIMPL
  | 5 -> REFUSED
  | x -> fmterror "RCODE %u" x

let describe_opcode = function 
  | 0 -> "QUERY"
  | 1 -> "IQUERY"
  | 2 -> "STATUS"
  | n -> sprintf "OPCODE %d" n
let describe_rcode rcode = try string_of_rcode (rcode_of_int rcode) with _ -> "?"

let class_in = 1 (* CLASS IN *)
let opcode_query = 0 (* OPCODE QUERY *)

(* 4.1.2. Question section format *)

let bits x = 8 * x
let string_bits x = 8 * String.length x

let get_question refstr =
  match domain_name !refstr with
  | None -> fmterror "owner name"
  | Some (tail,domain) ->
     bitmatch tail with
     | { qtype : 16; qclass : 16; :rest } ->
        let question = subbitstring !refstr 0 (32 + (domain >> labels_of_domain >> String.length >> bits)) in
        refstr := rest;
        if class_in = qclass then (qtype_of_int qtype, domain, question) else notimpl "QCLASS %u" qclass
     | { } -> fmterror "question section"

let just_get_question str = get_question (ref str)

(* 4.1.3. Resource record format *)

type domain = string list
type rr_record =
  | RR_None
  | RR_A of domain * int32 * ipv4
  | RR_CNAME of domain * domain
  | RR_SRV of domain * int32 * int * int * int * int * domain
  | RR_Unknown of int

(* parse answer (incomplete) *)
let get_answer refstr =
  match domain_name !refstr with
  | None -> RR_None
  | Some (tail,domain) ->
     bitmatch tail with
     | { 1 (* A *) : 16; 1 (* IN *) : 16; ttl : 32 : unsigned; 4 : 16; rdata : 32; :rest } -> refstr := rest; RR_A (domain,ttl,rdata)
     | { 5 (* CNAME *) : 16; 1 : 16; ttl : 32 : unsigned; n : 16; rdata : bits n : bitstring; :rest } -> refstr := rest;
        begin match domain_name rdata with
        | Some (tail,cname) when bitstring_length tail = 0 -> RR_CNAME (domain, cname)
        | _ -> RR_None
        end
     | { 33 (* SRV *) : 16; 1: 16; ttl : 32 : unsigned; n:16; prio : 16; wght : 16; port : 16; :rest } ->
       begin match domain_name rest with
         | Some (tail, target) ->
           RR_SRV (domain, ttl, n, prio, wght, port, target)
         | _ -> assert false
       end
     (* unknown record *)
     | { typ : 16; cls : 16; ttl : 32 : unsigned; n : 16; _rdata : bits n : bitstring; :rest } -> refstr := rest; RR_Unknown typ
     | { } -> RR_None

let hour = 3600l
let hours = Int32.mul hour
let day = hours 24l
let days = Int32.mul day
let default_ttl = hours 2l

let make_rr domain rtype ?(ttl=default_ttl) rdata =
  let name = labels_of_domain domain in
  let len = bitstring_length rdata in
  assert (0 = len mod 8);
  let len = len / 8 in
  BITSTRING {
    name : string_bits name : string;
    int_of_qtype rtype : 16;
    class_in : 16;
    ttl : 32 : unsigned;
    len : 16 : unsigned;
    rdata : 8 * len : bitstring
  }

let make_rr_a domain ?(ttl=default_ttl) addr =
  make_rr domain A ~ttl (BITSTRING { addr : 4*8 : unsigned })

let make_rr_txt domain ?ttl txt =
  assert (String.length txt < 256);
  make_rr domain TXT ?ttl (BITSTRING { String.length txt : 8; txt : string_bits txt : string })

let pkt_out out (pkt:pkt) =
  bitmatch pkt with
  | { :dns_header; :rest } ->
      IO.printf out "DNS: id %u\n" id;
      let flags = [qr,"qr"; aa,"aa"; tc,"tc"; rd,"rd"; ra,"ra"] >> List.filter_map (function (true,s) -> Some s | _ -> None) in
      IO.printf out "%s %s %s\n" (describe_opcode opc) (String.concat " " flags) (describe_rcode rcode);
      IO.printf out "qd# %d an# %d ar# %d ad# %d\n" qdcount ancount arcount adcount;
      let rest = ref rest in
      if qdcount > 0 then
      begin
        IO.printf out "Query: ";
        try
          let (qtype,domain,_) = get_question rest in
          IO.printf out "%s : %s\n" (string_of_qtype qtype) (string_of_domain domain)
        with
        | Error (_,reason) -> IO.printf out "error : %s\n" reason
        | exn -> IO.printf out "ERROR : %s\n" (Printexc.to_string exn)
      end;
      for _i = 1 to ancount do
        match get_answer rest with
        | RR_None -> IO.printf out "Answer: unrecognized\n"
        | RR_A (dom,ttl,addr) -> 
            IO.printf out "Answer: A %s ip %s ttl %ds\n"
              (string_of_domain dom) (string_of_ipv4 addr) (Int32.to_int ttl)
        | RR_CNAME (dom,cname) ->
            IO.printf out "Answer: CNAME %s %s\n" (string_of_domain dom) (string_of_domain cname)
        | RR_SRV (domain, ttl, n, prio, weight, port, target) ->
          IO.printf out "Answer: SRV %s %d %d %d %d %s\n" (string_of_domain domain) n prio weight port (string_of_domain target)
        | RR_Unknown n ->
            IO.printf out "Answer: Unknown (%d)\n" n
      done
  | { } -> IO.printf out "<?>\n"

let pkt_out_s pkt = 
  let out = IO.output_string () in
  pkt_out out pkt;
  IO.close_out out

let pkt_info (pkt:pkt) =
  let out = IO.output_string () in
  (bitmatch pkt with
  | { :dns_header; :rest } ->
      IO.printf out "%s %s" (describe_opcode opc) (describe_rcode rcode);
      let rest = ref rest in
      if qdcount > 0 then
      begin
        try
          let (qtype,domain,_) = get_question rest in
          IO.printf out " %s for %s" (string_of_qtype qtype) (string_of_domain domain)
        with
        | Error (_,reason) -> IO.printf out " error : %s" reason
        | exn -> IO.printf out " ERROR : %s" (Printexc.to_string exn)
      end;
      let ans = List.init ancount (fun _ ->
        match get_answer rest with
        | RR_None -> "?"
        | RR_A (_domain,_ttl,addr) -> "A " ^ string_of_ipv4 addr
        | RR_CNAME (_domain,cname) -> "CNAME " ^ string_of_domain cname
        | RR_Unknown n -> sprintf "? (%d)" n
        ) 
      in
      IO.printf out " {%s}" (String.concat "," ans)
  | { } -> IO.printf out "no dns header");
  IO.close_out out

(** parse DNS packet (only IN QUERY A and CNAME for now), extract question and answer sections *)
let parse s =
  bitmatch (to_pkt s) with
  | { :dns_header; :rest } ->
      if opc <> opcode_query then fail "Expected QUERY, got %s" (describe_opcode opc);
(*       if tc then Exn.fail "TrunCated"; *)
      let rest = ref rest in
      let qd = List.init qdcount (fun _ -> let (qtype,domain,_) = get_question rest in (qtype,domain)) in
      let an = List.init ancount (fun _ -> get_answer rest) >>
        List.filter_map 
        (function
        | RR_None | RR_Unknown _ -> None
        | RR_A (_domain,_ttl,addr) -> Some addr
        | RR_CNAME (_domain,_cname) -> None)
      in
      let info = match qr with
      | false -> `Query rd
      | true -> `Reply (rcode_of_int rcode,aa,ra)
      in
      id, info, qd, an
  | { } -> fail "no dns header"

(* --- From bitstring 2.0.0 *)

(* Concatenate bitstrings. *)
let concat_bs bs =
  let buf = Buffer.create () in
  List.iter (construct_bitstring buf) bs;
  Buffer.contents buf

(* --- *)

let make_reply_packet rcode id opc rr_qd (rr_an,rr_ns,rr_ar) =
  let qr = true and aa = true and tc = false and rd = false and ra = false in
  let hdr = BITSTRING 
  {
    id : 16;
    qr : 1; opc : 4; aa : 1; tc : 1; rd : 1; ra : 1; 0 : 3; int_of_rcode rcode : 4;
    List.length rr_qd : 16;
    List.length rr_an : 16;
    List.length rr_ns : 16;
    List.length rr_ar : 16
  }
  in concat_bs (hdr :: List.flatten [rr_qd; rr_an; rr_ns; rr_ar])

let make_soa_rdata d =
  let mname = d.ns >> List.hd >> domain_of_string >> labels_of_domain in
  let rname = "hostmaster" :: (domain_of_string d.name) >> labels_of_domain in
  let serial = 1l
  and refresh = hour
  and retry = hour
  and expire = days 14l
  and minimum = default_ttl 
  in
  BITSTRING
  {
    mname : string_bits mname : string;
    rname : string_bits rname : string;
    serial : 32 : unsigned;
    refresh : 32 : unsigned;
    retry : 32 : unsigned;
    expire : 32 : unsigned;
    minimum : 32 : unsigned
  }

let make_rr_ns domain name =
  let ns = labels_of_domain (domain_of_string name) in (* FIXME *)
  make_rr domain NS (BITSTRING { ns : string_bits ns : string })

let make_rr_soa d =
  make_rr (domain_of_string d.name) SOA (make_soa_rdata d)

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

let describe_exn exn =
  let (rcode,reason) = match exn with Error (rc,s) -> rc,s | exn -> SERVFAIL, Printexc.to_string exn in
  rcode, sprintf "%s : %s" (string_of_rcode rcode) reason

let make_reply_exn (query:pkt) answer ~on_error k =
  bitmatch query with
  | { :dns_header; :rest } -> 
    begin
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
    end
  | { } -> failwith "no dns header"

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

(** DNS ID is 16-bit *)
let max_id = 0xffff

(* build A IN query packet *)
let query_pkt_a id name =
  let qr = false and aa = false and tc = false and rd = true and ra = false in
  let rcode = 0 in
  let id = id land max_id in
  let domain = labels_of_domain name in
  let qtype = 1 (* A *) and qclass = class_in and opc = opcode_query in
  BITSTRING {
    id : 16;
    qr : 1; opc : 4; aa : 1; tc : 1; rd : 1; ra : 1; 0 : 3; rcode : 4;
    1 : 16;
    0 : 16;
    0 : 16;
    0 : 16;
    domain : 8 * String.length domain : string;
    qtype : 16;
    qclass : 16
  }

let make_query_a id domain = of_pkt & query_pkt_a id & domain_of_string domain

