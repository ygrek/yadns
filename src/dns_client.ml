(** Example: simple command-line DNS lookup utility *)

open Unix
open ExtLib
open Printf

open Dns_utils

module Dns = Dns_format

let maxlen = 1024
let timeout = 5

let with_unix_error f x =
   begin try
     f x;
   with
   | Unix_error (err,func,param) -> Printf.eprintf "Unix_error %s %s(%s)" (error_message err) func param
   end

let sock = socket PF_INET SOCK_DGRAM (getprotobyname "udp").p_proto

let start = Unix.gettimeofday ()

let buffer = String.create maxlen

let ask sockaddr typ domain =
    let pkt = Dns.make_query (Random.int Dns.max_id + 1) typ domain in
    ignore (sendto sock pkt 0 (String.length pkt) [] sockaddr);
(*    Sys.set_signal Sys.sigalrm (Sys.Signal_handle handle_alarm);
    ignore (alarm timeout);*)
    let msg =
      match recvfrom sock buffer 0 maxlen [] with
      | len, ADDR_INET (_,_) -> String.sub buffer 0 len
      | _ -> assert false 
    in
    Dns.pkt_out (IO.output_channel Pervasives.stdout) (Dns.to_pkt msg);
    print_endline ""
(*    ignore (alarm 0);*)
(*
    Printf.printf "Server %s responded\n" hishost;
    Dns.pkt_out out (Dns.to_pkt msg);
    IO.flush out
*)

let read_resolv_conf () =
  let l =
    try
      let ch = open_in "/etc/resolv.conf" in
      let l = List.of_enum & Std.input_lines ch in
      close_in ch;
      l
    with _ -> []
  in
  List.filter_map (fun s -> try Scanf.sscanf s "nameserver %s %!" (fun s -> Some (s,53)) with _ -> None) l

let main () =
  let (qtype,servers,domains) =
    match Array.to_list & Sys.argv with
    | [] -> assert false
    | [prog] -> eprintf "Usage: %s [A|NS|SRV|...] domain [@server[:port]]\n%!" prog; exit 1
    | _::x::xs ->
      let (qtype,l) = try Dns.qtype_of_string x, xs with _ -> Dns.A, x::xs in
      let (servers,domains) = List.partition (fun s -> String.starts_with s "@") l in
      let servers = List.map (fun s ->
        try Scanf.sscanf s "@@%s:%d%!" (fun s n -> s,n) with _ -> String.slice ~first:1 s, 53) servers
      in
      let servers = if servers = [] then read_resolv_conf () else servers in
      qtype, servers, domains
  in
  if servers = [] then (prerr_endline "No servers to query"; exit 1);
  if domains = [] then (prerr_endline "Nothing to query"; exit 1);
  let servers = List.map (fun (s,p) -> (s,p), lazy (ADDR_INET ((gethostbyname s).h_addr_list.(0), p))) servers in
  Random.self_init ();
  let next =
    let l = ref servers in
    let rec loop () = match !l with [] -> l := servers; loop () | x::xs -> l := xs; x in
    loop
  in
(*   for i = 0 to 1_000_000 do *)
    List.iter (fun s ->
      let ((server,port),sockaddr) = next () in
      printf ">> query %s %s at %s:%d\n%!" (Dns.string_of_qtype qtype) s server port; 
      ask (Lazy.force sockaddr) qtype s) domains;
(*     if 0 = !dns_id mod 1000 then printf "%f %u\n%!" (Unix.gettimeofday () -. start) !dns_id; *)
(*   done; *)
  ()

let main = with_unix_error main

let () =
  Printexc.print main ()
