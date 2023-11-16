(declare-project
  :name "jcraft"
  :description "toy Minecraft server implementation"
  :dependencies [
    {:url "https://github.com/ianthehenry/judge.git"
     :tag "v2.7.0"}
    {:url "https://github.com/janet-lang/jhydro.git"}
    {:url "https://github.com/andrewchambers/janet-sh"}
    {:url "https://github.com/janet-lang/spork"} 
])

(declare-native
  :name "ssl"
  :source ["ssl.c"]
  :lflags ["-lssl" "-lcrypto" "-lcurl"])
