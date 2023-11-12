deps:
	jpm deps -l

build:
	jpm install -l --buildpath=rsa
	jpm -l janet server.janet

compile:
	jpm install -l --buildpath=rsa
	jpm -l janet -c server.janet jcraft.jimage

clean:
	jpm clean
