
open Unix
open Prelude
open ExtLib
open Printf

open Dns_utils

module Dns = Dns_format

let maxlen  = 1024
let server_host = ref "127.0.0.1"
let server_port  = ref 53
let timeout = 5

let with_unix_error f x =
   begin try
     f x;
   with
   | Unix_error (err,func,param) -> Printf.eprintf "Unix_error %s %s(%s)" (error_message err) func param
   end

let sock = socket PF_INET SOCK_DGRAM (getprotobyname "udp").p_proto

let handle_alarm _ =
  Printf.eprintf "recv from %s timed out after %d seconds.\n" !server_host timeout;
  exit 1

let dns_id = ref 0
let make_query domain = incr dns_id; Dns.of_pkt (Dns.query_pkt_a !dns_id domain)
let start = Unix.gettimeofday ()

let buffer = String.create maxlen

let ask sockaddr domain =
    let pkt = make_query domain in
    ignore (sendto sock pkt 0 (String.length pkt) [] sockaddr);
(*    Sys.set_signal Sys.sigalrm (Sys.Signal_handle handle_alarm);
    ignore (alarm timeout);*)
    let msg =
      match recvfrom sock buffer 0 maxlen [] with
      | len, ADDR_INET (_,_) -> String.sub buffer 0 len
      | _ -> assert false 
    in
    Dns.pkt_out (IO.output_channel Pervasives.stdout) (Dns.to_pkt msg)
(*    ignore (alarm 0);*)
(*  
    Printf.printf "Server %s responded\n" hishost;
    Dns.pkt_out out (Dns.to_pkt msg);
    IO.flush out
*)

let set x y = x := y

let main () =
  let args =
  [
    "-host", Arg.String (set server_host), "<host> Set server host";
    "-port", Arg.Int (set server_port), "<num> Set server port";
  ]
  in
  let domains = ref [] in
  Arg.parse (Arg.align args) (fun s -> domains := s :: !domains) "try -help";
  let sockaddr =
    let addr = (gethostbyname !server_host).h_addr_list.(0) in
    ADDR_INET (addr, !server_port)
  in
  printf "Will query %s:%u for %u domains\n%!" !server_host !server_port (List.length !domains);
  Random.self_init ();
  let out = IO.output_channel Pervasives.stdout in
  let input = IO.input_channel Pervasives.stdin in
(*   for i = 0 to 1_000_000 do *)
    List.iter (fun s -> ask sockaddr (domain_of_string s)) !domains;
(*     if 0 = !dns_id mod 1000 then printf "%f %u\n%!" (Unix.gettimeofday () -. start) !dns_id; *)
(*   done; *)
  IO.close_out out;
  IO.close_in input

let main = with_unix_error main

let () =
  Printexc.print main ()
