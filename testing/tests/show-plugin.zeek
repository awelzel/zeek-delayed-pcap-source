# @TEST-EXEC: zeek -NN Zeek::DelayedPcapSource |sed -e 's/version.*)/version)/g' >output
# @TEST-EXEC: btest-diff output
