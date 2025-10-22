PWD=$(shell pwd)

target.bpf: constants.json target.seccomp
	minijail/tools/compile_seccomp_policy.py target.seccomp target.bpf

minijail:
	git clone https://android.googlesource.com/platform/external/minijail/ minijail

constants.json: minijail
	make OUT=${PWD}/minijail -C minijail constants.json
	cp minijail/constants.json .

target.strace: ../zig-out/bin/klutshnikd
	cd ../../test && ORACLE_STRACE=1 ./easy-test.sh
	cp ../../test/servers/1/strace.log ./target.strace

target.seccomp: target.strace
	minijail/tools/generate_seccomp_policy.py target.strace >target.seccomp

../zig-out/bin/klutshnikd:
	cd .. && zig build -Doptimize=Debug -freference-trace=11 -Dpie=true -Drelro=true -Dsystem_libs=false

clean:
	rm -rf minijail constants.json target.strace target.seccomp target.bpf
