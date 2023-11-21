(use jhydro)
(use judge)
(import spork/json :as json)
(import ./ssl/ssl :as ssl)

# The actual server
(def minecraft-server (net/listen "127.0.0.1" "25565"))

# Timeout for reading data in seconds
(def TIMEOUT 10)

# Maximum sizes of various datatypes
(def datatype-size-table @{
                           :boolean 1
                           :byte 1
                           :unsigned-byte 1
                           :short 3
                           :unsigned-short 2
                           :int 4
                           :long 8
                           :float 4
                           :double 8
                           :chat (+ (* 262144 4) 3)
                           :identifier (+ (* 32767 4) 3)
                           :varint 5
                           :varlong 10
                           :position 8
                           :angle 1
                           :uuid 16
                           })

(defn calc-size
  "Calculates the packer header size"
  [& types]
  (match types
    (tuple) 0
    [:string n & rest] (+ (+ 3 (* 4 n)) (calc-size ;rest))
    [:byte-array n & rest] (+ n (calc-size ;rest))
    [head & rest] (+ (datatype-size-table head) (calc-size ;rest)))
  )
(test (calc-size :string 34 :varint :varint) 149)
(test (calc-size :varint :varint :boolean :boolean :position) 20)

(defn get-pkt-size
  "Gets the packet size, including the header"
  [& types]
  (calc-size :varint :varint ;types))
(test (get-pkt-size :varint :string 255 :unsigned-short :varint) 1045) # handshake
(test (get-pkt-size :string 16 :uuid) 93) # login start

# <Generation of public/private key pair>
(def SERVER_INFO (ssl/new))
(def SERVER_PUBLIC_KEY (ssl/der SERVER_INFO))
# </Generation of public/private key pair>

# Endpoint for server-side authentication
(def ENCRYPTION_ENDPOINT "https://sessionserver.mojang.com/session/minecraft/hasJoined")

(defn make-byte-fiber
  "Makes a fiber that generates the next byte from a buffer"
  [buf]
  (generate [i :range [0 (length buf)]] (i buf)))

(defn next-byte
  "Gets the next byte from a fiber made by make-byte-fiber"
  [byte_fiber]
  (if (not= :dead (fiber/status byte_fiber))
  (resume byte_fiber)))

# See https://wiki.vg/Protocol#VarInt_and_VarLong
(defn read-varint
  "Reads a varint according to LEB128 signed encoding"
  [buf]
  (def segment_bits 0x7F)
  (def continue_bits 0x80)
  (var pos 0)
  (var value 0)
  (while (< pos 32)
    (def cur_byte (next-byte buf))
    (set value (bor value (blshift (band cur_byte segment_bits) pos)))
    (if (= (band cur_byte continue_bits) 0)
      (break))
    (+= pos 7))
  value)

(defn write-varint
  "Writes an integer to LEB128 signed encoding"
  [buf value]
  (def segment_bits 0x7F)
  (def continue_bit 0x80)
  (var bytes 0)
  (var v value)
  (forever
    (if (= 0 (band v (bnot segment_bits)))
      (do
        (++ bytes)
        (buffer/push-byte buf v)
        (break)))
    (++ bytes)
    (buffer/push-byte buf (bor (band v segment_bits) continue_bit))
    (set v (brshift v 7)))
  bytes)

(defn read-unsigned-short
  "Reads an unsigned short"
  [buf]
  (def first_byte (next-byte buf))
  (def second_byte (next-byte buf))
  (bor (blshift first_byte 8) second_byte))

(defn read-string
  "Read a string from a fiber"
  [buf n]
  (def strlen (read-varint buf))
  (if (< strlen n)
    (buffer/push-byte @"" ;(take strlen buf)) nil))

(defn write-string 
  "Writes a string to a buffer"
  [buf str]
  (write-varint buf (length str))
  (buffer/push-string buf str))
  
(defn read-uuid
  "Reads 16 bytes corresponding to a UUID"
  [buf]
  (take 16 buf))

(defn read-byte-array
  "Reads a byte array of specified length"
  [buf len]
  (buffer/push-byte @"" ;(take len buf)))

(defn write-byte-array
  "Writes a byte array"
  [buf bytes]
  (buffer/push buf bytes))

(defn make-pairs
  "Groups elements into 2-tuples"
  [& elems]
  (match elems
    (tuple) @[]
    [x y & rest] (array/concat @[@[x y]] (make-pairs ;rest)))
 )

(defn tupleify
  "Makes second argument of tuple into a tuple if not already one"
  [twotuple]
  (def [x y] twotuple)
  (if (indexed? y) twotuple (tuple x (tuple y))))

(defmacro read-bytes
  "Reads a packet according to the given layout"
  [pkt_fiber & read-types]
  (with-syms [$parsed-table $tuple-pairs]
     ~(upscope
        (def ,$parsed-table ,@{})
        (def ,$tuple-pairs (map tupleify (make-pairs ,;read-types)))
        # If we have something like [:string 255] or [:byte-array 100], then
        # (first (1 kv)) will get the :string/:byte-array part, and the
        # tuple/slice will get the 255/100 part and splice them as arguments
        (map (fn [kv] (put ,$parsed-table (0 kv) ((eval (symbol (string "read-" (first (1 kv))))) ,pkt_fiber ;(tuple/slice (1 kv) 1)))) ,$tuple-pairs)
        ,$parsed-table)
     )
  )

(defmacro write-bytes
  "Writes a packet according to the given layout"
  [buf & write-types]
  (with-syms [$tuple-pairs]
    ~(upscope
       (def ,$tuple-pairs (map tupleify (make-pairs ,;write-types)))
       (map (fn [kv] ((eval (symbol (string "write-" (0 kv)))) ,buf ;(1 kv))) ,$tuple-pairs)
     )))

(defn read-pkt
  "Reads the data of the packet"
  [connection & pkt-layout]
  (def size (get-pkt-size ;(flatten (values (table ;pkt-layout)))))
  (def buf (ev/read connection size nil TIMEOUT))
  (def bytes (make-byte-fiber buf))
  (read-bytes bytes :packet_size :varint :packet_id :varint ;pkt-layout))

(defn write-pkt
  "Writes data as packet"
  [connection id & pkt-layout]
  (def pkt @"") # packet data + packet header
  (def pkt-data @"")
  (write-bytes pkt-data ;pkt-layout)
  # Packet header
  (def idbuf @"")
  (def idbytes (write-varint idbuf id))
  (write-varint pkt (+ (length pkt-data) idbytes))
  (buffer/push pkt idbuf)
  # Packet data
  (buffer/push pkt pkt-data)
  (ev/write connection pkt TIMEOUT))

(defn calc-client-hash
  "Calculates the SHA1 hex digest"
  [shared_secret]
  (string/ascii-lower (ssl/sha1 shared_secret SERVER_PUBLIC_KEY)))
(test (string/ascii-lower (ssl/sha1 @"" @"jeb_")) "-7c9d5b0044c130109a5d7b5fb5c317c02b4e28c1")
(test (string/ascii-lower (ssl/sha1 @"" @"Notch")) "4ed1f46bbe04bc756bcb17c0c7ce3e4632f06a48")
(test (string/ascii-lower (ssl/sha1 @"" @"simon")) "88e16a1019277b15d58faf0541e11910eb756f6")

(defn send-auth-req
  "Sends an authentication request"
  [name client_hash]
  (def mojang_url (string ENCRYPTION_ENDPOINT "?username=" name "&serverId=" client_hash)) 
  (ssl/get mojang_url))

(defn handle-encryption
  "Handles setting up encryption"
  [connection name uuid]
  (def verify_token @"")
  (random/buf verify_token 4)
  (write-pkt connection 0x1 :string "" :varint (length SERVER_PUBLIC_KEY) :byte-array SERVER_PUBLIC_KEY :varint (length verify_token) :byte-array verify_token)
  (def encryption_response (read-pkt connection :shared_secret_len :varint :shared_secret [:byte-array 128] :verify_token_len :varint :verify_token [:byte-array 128]))
  (def decrypted_verify_token (ssl/decrypt SERVER_INFO (get encryption_response :verify_token)))
  (if (deep= decrypted_verify_token verify_token)
    (do 
      (def decrypted_shared_secret (ssl/decrypt SERVER_INFO (get encryption_response :shared_secret)))
      (def client_hash (calc-client-hash decrypted_shared_secret))
      (def resp (send-auth-req name client_hash))
      (def resp_data (json/decode resp))
      (printf "%j" resp_data)
      (def aes_info (ssl/setup-aes decrypted_shared_secret))
      # (write-pkt connection 0x2 :uuid uuid :string name :varint num_props
                   # :string resp_data_name :string resp_data_value :boolean
                   # false)
      )))
# TODO
(defn handle-status
  "Handle status=1 in handshake"
  [connection])

(defn handle-login-start
  "Handles status=2 in handshake"
  [connection]
  (def login-start-result (read-pkt connection :username [:string 16] :userid :uuid))
  (handle-encryption connection (login-start-result :username) (login-start-result :userid)))

(defn main-server-handler
  "Handle connection in a separate fiber"
  [connection]
  (defer (:close connection)
    (def handshake_result (read-pkt connection :protocol_num :varint :server_address [:string 255] :server_port :unsigned-short :state :varint))
    (if (= 2 (get handshake_result :state))
      (handle-login-start connection) (handle-status connection))))

# Uncomment below when running `judge`
# (quit)

# Main code
(print "Server is up and ready")
(forever
  (def conn (net/accept minecraft-server))
  (ev/call main-server-handler conn)) 
