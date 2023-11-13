(declare-project
  :name "jcraft"
  :description "toy Minecraft server implementation"
  :dependencies [
    {:url "https://github.com/ianthehenry/judge.git"
     :tag "v2.7.0"}
    {:url "https://github.com/janet-lang/jhydro.git"}
    {:url "https://github.com/andrewchambers/janet-sh"} 
])

(declare-native
  :name "rsa"
  :source ["ssl.c"]
  :cflags [;default-cflags "-lssl" "-lcrypto" "-lcurl"])
