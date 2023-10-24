# The actual server
(def minecraft-server (net/listen "127.0.0.1" "25565"))

# Maximum sizes of various datatypes
(def datatype-size-table @{
                           :varint 5
                           :unsigned_short 2
})

(defn get-size
  "Gets the max size of a datatype (if it's a string, the optional size is used for calculation)"
  [name &opt size]
  (if (compare= name :string)
    (+ (* 4 size) 3)
    (get datatype-size-table name)))

(defn calc_handshake_size
  "Calculates the maximum size of the handshake data (excluding packet headers)"
  []
  (+ (get-size :varint) (get-size :string 255) (get-size :unsigned_short) (get-size :varint)))

(defn calc_packet_header_size
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

(defn parse-packet-header
  "Gets the packet size and its ID"
  [packet_data]
  (def packet_size (read-varint packet_data))
  (def packet_id (read-varint packet_data))
  @{ :packet_size packet_size
     :packet_id packet_id
   })

(defn parse-handshake-msg
  [handshake_msg]
  "Parses the handshake data"
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

(defn main-server-handler
  "Handle connection in a separate fiber"
  [connection]
  (defer (:close connection)
    (def packet_data (make-byte-fiber (ev/read connection (+ (calc_handshake_size) (calc_packet_header_size)))))
    (def packet_header (parse-packet-header packet_data))
    (print "Packet size: " (get packet_header :packet_size))
    (print "Packet id: " (get packet_header :packet_id))
    (def handshake_result (parse-handshake-msg packet_data))
    (map (fn [x] (print x ": " (handshake_result x))) (keys handshake_result))))

# Main code
(forever
  (def conn (net/accept minecraft-server))
  (ev/call main-server-handler conn))
