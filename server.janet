# The actual server
(def minecraft-server (net/listen "127.0.0.1" "25565"))

# Maximum sizes of various datatypes
(def datatype-size-table @{
                           :varint 5
                           :unsigned_short 2
                           :uuid 16
})

(defn get-size
  "Gets the max size of a datatype (if it's a string, the optional size is used for calculation)"
  [name &opt size]
  (if (compare= name :string)
    (+ (* 4 size) 3)
    (get datatype-size-table name)))

(defn calc-handshake-size
  "Calculates the maximum size of the handshake data (excluding packet header)"
  []
  (+ (get-size :varint) (get-size :string 255) (get-size :unsigned_short) (get-size :varint)))

(defn calc-login-start-size
  "Calculates the maximum size of the login start data (excluding packet header)"
  []
  (+ (get-size :string 16) (get-size :uuid)))

(defn calc-packet-header-size
  "Calculates the packer header size"
  []
  (+ (get-size :varint) (get-size :varint)))

(defn make-byte-fiber
  "Makes a fiber that generates the next byte from a buffer"
  [buf]
  (generate [i :range [0 (length buf)]] (i buf)))

(defn next-byte
  "Gets the next byte from a fiber made by make-byte-fiber"
  [byte_fiber]
  (resume byte_fiber))

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

(defn read-unsigned-short
  "Reads an unsigned short"
  [buf]
  (def first_byte (next-byte buf))
  (def second_byte (next-byte buf))
  (bor (blshift first_byte 8) second_byte))

(defn read-string
  "Read a string from a fiber"
  [buf]
  (def strlen (read-varint buf))
  (var strbuf @"")
  (map (fn [x] (buffer/push-word strbuf x)) (take strlen buf))
  strbuf)

(defn read-uuid
  [buf]
  (take 16 buf))

(defn parse-packet-header
  "Gets the packet size and its ID"
  [packet_data]
  (def packet_size (read-varint packet_data))
  (def packet_id (read-varint packet_data))
  @{ :packet_size packet_size
     :packet_id packet_id
   })

(defn parse-handshake-msg
  "Parses the handshake data"
  [handshake_msg]
  (def protocol_num (read-varint handshake_msg))
  (def server_address (read-string handshake_msg))
  (def server_port (read-unsigned-short handshake_msg))
  (def state (read-varint handshake_msg))
  @{
    :protocol_num protocol_num
    :server_address server_address
    :server_port server_port
    :state state
  })

(defn handle-status
  "Handle status=1 in handshake"
  [connection])

(defn handle-login-start
  "Handles status=2 in handshake"
  [connection]
  (def packet_data (make-byte-fiber (ev/read connection (+ (calc-login-start-size) (calc-packet-header-size)))))
  (def packet_header (parse-packet-header packet_data))
  (def name (read-string packet_data))
  (def uuid (read-uuid packet_data))
  (print name)
  (print (string/join (map (fn [x] (string/format "%x" x)) uuid))))

(defn main-server-handler
  "Handle connection in a separate fiber"
  [connection]
  (defer (:close connection)
    (def packet_data (make-byte-fiber (ev/read connection (+ (calc-handshake-size) (calc-packet-header-size)))))
    (def packet_header (parse-packet-header packet_data))
    (def handshake_result (parse-handshake-msg packet_data))
    (if (= 2 (get handshake_result :state))
      (handle-login-start connection) (handle-status connection))))

# Main code
(forever
  (def conn (net/accept minecraft-server))
  (ev/call main-server-handler conn))
