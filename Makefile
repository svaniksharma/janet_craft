deps:
	jpm deps -l

build:
	jpm install -l --buildpath=rsa
	jpm -l janet server.janet

clean:
	jpm clean
