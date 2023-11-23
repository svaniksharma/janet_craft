(import spork/json :as json)
(import spork/argparse)

# Converts JSON encoding of NBT (Minecraft version 1.20.2) to binary network NBT
# format

(def TAG-TYPE @{
                :end 0x0
                :byte 0x1
                :short 0x2
                :int 0x3
                :long 0x4
                :float 0x5
                :double 0x6
                :byte-array 0x7
                :string 0x8
                :list 0x9
                :compound 0xA
                :int-array 0xB
                :long-array 0xC
                })

(defn write-tag-end
  [nbt-file]
  (file/write nbt-file @"\x00\x00"))

(defn write-tag-byte
  [nbt-file byte]
  (file/write nbt-file (band byte 0xFF)))

(defn write-tag-short
  [nbt-file short])

(defn write-tag-int
  [nbt-file int])

(defn write-tag-long
  [nbt-file long])

(defn write-tag-float
  [nbt-file float])

(defn write-tag-double
  [nbt-file double])

(defn write-tag-byte-array
  [nbt-file byte-array])

(defn write-tag-string
  [nbt-file str])

(defn write-tag-list
  [nbt-file tag-type list]
  (file/write nbt-file (buffer/push-byte @"" (TAG-TYPE tag-type)))
  # Length returns positive values, so no need to worry about signedness
  (file/write nbt-file (int/to-bytes (band (int/s64 (length list)) 0xFFFFFFFF) :be))
  (map (eval (symbol (string "write-tag-" tag-type))) list))

(defn write-tag-compound
  [nbt-file name compound-payload]
  (file/write nbt-file (TAG-TYPE :compound))
  (write-tag-int nbt-file (length name))
  (write-tag-string nbt-file name)
  # compound-payload is a tuple of (write-func, data)
  (map (fn [kv] ((0 kv) (1 kv))) compound-payload)
  (write-tag-end nbt-file))

(defn write-tag-int-array
  [nbt-file int-array])

(defn write-tag-long-array
  [nbt-file long-array])

(defn write-registry
  [nbt-file registry]
  (pp (registry "value"))
  (quit)
  (write-tag-string nbt-file (registry "type"))
  (write-tag-list nbt-file :compound (registry "value")))

(def res (argparse/argparse ;["Converts JSON to NBT format" 
                              "infile" {:kind :option :short "i" :required true} 
                              "outfile" {:kind :option :short "o" :required true}]))

(def json-file-name (res "infile"))
(def nbt-file-name (res "outfile"))
(def nbt-file (file/open nbt-file-name :a))
(def data (json/decode (slurp json-file-name)))
# For Minecraft 1.20.2+, network NBT does not have a name and length field
(file/write nbt-file (buffer/push-byte @"" (TAG-TYPE :compound)))
(loop [key :in (keys data)]
  (write-registry nbt-file (data key)))
(file/close nbt-file)
