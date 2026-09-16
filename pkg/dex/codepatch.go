package dex

import "fmt"

// InsertPayloadCall splices `invoke-static {}, L<payloadClass>;-><payloadMethod>()V`
// into an existing method body of a class the host already runs, so the payload
// executes without any manifest change (vectors 9 and 11).
//
// NOT IMPLEMENTED YET. What remains, and why it is not a small change:
//
//   - The patched method lives in a *host* dex, so the result has to be a valid
//     dex again. Re-emitting the whole file through Parse/Encode (the path the
//     tool's own stub dex takes) needs the parser to round-trip arbitrary
//     real-world dex files. Three real bugs in that path were found and fixed
//     while implementing this vector (opcode read from the wrong byte in
//     insns.go, debug opcode read as uleb128 in parse.go, and the missing
//     payload case in the instruction walk); more sections (annotations,
//     encoded values, static values) are still unverified on host files, so a
//     full round trip is not safe yet.
//
//   - The cheaper, growth-free alternative is to leave the host file's existing
//     items alone and append the rewritten class_data_item + code_item at the
//     end of the file: rewrite the class_def's class_data_off (a fixed-width
//     u32 in place), append the new items, extend/relocate the map list, fix
//     file_size/data_size and recompute the SHA-1 signature + adler32. No
//     offset in the existing file moves, which is what makes this safe.
//
//     The catch is ids: the inserted call must reference a method_id that the
//     host dex already contains — adding one would grow the ids tables and
//     shift everything. Host dexes do carry such ids: references to classes the
//     APK never ships (optional dependencies). Measured on the 50-host corpus:
//     25 hosts / 183 such references, i.e. the same trick as the sideload
//     vector ("make the lookup the host already performs succeed, with our
//     code behind it"). Building the payload class under that name is the
//     rename path already proven for the stub dex.
//
// Until that lands, the vector reports itself as not applicable instead of
// producing a half-patched dex.
func InsertPayloadCall(data []byte, classDescriptors []string, methodNames []string, payloadClass, payloadMethod string) ([]byte, []string, error) {
	return nil, nil, fmt.Errorf("code-item patch not implemented: host-dex rewrite pending (see InsertPayloadCall doc comment)")
}
