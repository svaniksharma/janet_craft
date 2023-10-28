# The actual server
(def minecraft-server (net/listen "127.0.0.1" "25565"))

# Timeout for reading data in seconds
(def TIMEOUT 10)

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

(defn calc-packet-header-size
  "Calculates the packer header size"
  []
  (+ (get-size :varint) (get-size :varint)))

(defn calc-handshake-size
  "Calculates the maximum size of the handshake data (excluding packet header)"
  []
  (+ (calc-packet-header-size) (get-size :varint) (get-size :string 255) (get-size :unsigned_short) (get-size :varint)))

(defn calc-login-start-size
  "Calculates the maximum size of the login start data (excluding packet header)"
  []
  (+ (calc-packet-header-size) (get-size :string 16) (get-size :uuid)))

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
  [buf &opt return_bytes]
  (def segment_bits 0x7F)
  (def continue_bits 0x80)
  (var pos 0)
  (var value 0)
  (var bytes 0)
  (while (< pos 32)
    (def cur_byte (next-byte buf))
    (++ bytes)
    (set value (bor value (blshift (band cur_byte segment_bits) pos)))
    (if (= (band cur_byte continue_bits) 0)
      (break))
    (+= pos 7))
  (if return_bytes @{:value value :bytes bytes} value))

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
  (def {:value packet_size :bytes packet_size_bytes} (read-varint packet_data true))
  (def {:value packet_id :bytes packet_id_bytes} (read-varint packet_data true))
  (def packet_header_size (+ packet_size_bytes packet_id_bytes))
  @{ :packet_size packet_size
     :packet_id packet_id
     :packet_id_bytes packet_id_bytes
     :packet_header_size packet_header_size
   })

(defn read-pkt
  "Reads the data of the packet"
  [connection size]
  (def buf (ev/read connection size nil TIMEOUT))
  (def bytes (make-byte-fiber buf))
  (def packet_header (parse-packet-header bytes))
  (def start (get packet_header :packet_header_size))
  (def nbytes (- (get packet_header :packet_size) (get packet_header :packet_id_bytes)))
  (make-byte-fiber (buffer/slice buf start (+ start nbytes))))

(defn parse-handshake-msg
  "Parses the handshake data"
  [handshake_msg]
  (def protocol_num (read-varint handshake_msg))
  (def server_address (read-string handshake_msg))
  (def server_port (read-unsigned-short handshake_msg))
  (def state (read-varint handshake_msg))
  @{ :protocol_num protocol_num
     :server_address server_address
     :server_port server_port
     :state state
  })

# TODO
(defn handle-encryption
  "Handles setting up encryption"
  [connection name uuid]
  (print name))

(defn handle-status
  "Handle status=1 in handshake"
  [connection])

(defn handle-login-start
  "Handles status=2 in handshake"
  [connection]
  (def packet_data (read-pkt connection (calc-login-start-size)))
  (def name (read-string packet_data))
  (def uuid (read-uuid packet_data))
  (handle-encryption connection name uuid))

(defn main-server-handler
  "Handle connection in a separate fiber"
  [connection]
  (defer (:close connection)
    (def packet_data (read-pkt connection (calc-handshake-size)))
    (def handshake_result (parse-handshake-msg packet_data))
    (if (= 2 (get handshake_result :state))
      (handle-login-start connection) (handle-status connection))))

# Main code
(forever
  (def conn (net/accept minecraft-server))
  (ev/call main-server-handler conn))
