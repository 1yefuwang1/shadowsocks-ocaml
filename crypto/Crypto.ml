open Core
open Cryptokit

(** only aes-cfb-256 is supported for now *)

let encrypt ~iv ~key ~text () =
  let open Cipher in
  let cipher = aes ~mode:(CFB 256) ~pad:Padding.length ~iv key Encrypt in
  transform_string cipher text

(** expand [password] to a key of size required by cipher *)
let password_to_key ~password ~iv_len ~key_len () =
  let total_len = iv_len + key_len in
  let queue = Queue.create () in
  while Queue.length queue * Md5.digest_num_bytes < total_len do
    let data =
      if Queue.is_empty queue
      then password
      else String.concat [ Queue.last_exn queue; password ]
    in
    let md5sum = Md5.digest_string data |> Md5.to_binary in
    Queue.enqueue queue md5sum
  done;
  let s = Queue.to_list queue |> String.concat in
  String.sub s ~pos:0 ~len:key_len

let%expect_test "password_to_key" =
  let password = "fuck" in
  let iv_len = 16 in
  let key_len = 32 in
  let key = password_to_key ~password ~iv_len ~key_len () in
  String.iter key ~f:(fun chr -> printf "%02x" (int_of_char chr));
  [%expect{|99754106633f94d350db34d548d6091a1ab93c2692a0a0465989239c22b45d7e|}]
