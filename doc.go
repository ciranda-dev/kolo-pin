// Package pin runs and uses pinning peers: a peer that stores encrypted data for others without being able to read it.
//
// A pinning peer keeps kolo-log logs available while their owners are offline. Serve runs one on a kolo-secure
// listener. Add makes it pull an owner's log over kolo-sync, as a replica without entry keys, under a capability
// the owner signed; Status and Remove ask about or delete a log, and Revoke delivers a revoke note. Any kolo-sync
// client pulls or fetches the hosted logs from it like from any other replica, as ciphertext only. Select and
// AddMany spread a log over several pinning peers.
//
// Experimental: the API may change before v1.0.0.
package pin
