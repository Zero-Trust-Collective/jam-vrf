# Crypto

Tram uses [VRF cryptography](https://github.com/davxy/bandersnatch-vrfs-spec) as an on-chain randomness beacon, and to determine block authorship rights. **Crpto** is a cryptography binding library for the [ark-ec-vrf library](https://github.com/davxy/ark-ec-vrfs/tree/main). This libary is a lightweight rust library that provides a python->rust ffi interface to the ark-ec-vrf rust library. The ark-ec-vrf library uses [arkworks](https://github.com/arkworks-rs) to provide both singly-contextualized & [ring](https://en.wikipedia.org/wiki/Ring_signature) VRF signing/verifying capabilities.

## Contributing

### Updating the FFI Lib

When attempting to propogate updates from the crypto library to the conductor, sometimes the conductor requires a fresh install of the crypto lib in order to pick up the changes. Once we settle on a project versioning strategy, incrementing the crypto lib version should also be a viable approach for this issue.
