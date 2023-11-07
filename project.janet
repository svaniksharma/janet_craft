(declare-project :name "rsa")

(declare-native
  :name "rsa"
  :source ["ssl.c"]
  :cflags [;default-cflags "-lssl" "-lcrypto"])
