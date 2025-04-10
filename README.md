# jam-vrf

Lightweight python bindings over the [ark-vrf](https://crates.io/crates/ark-vrf) crate for verifying JAM vrf signatures.. This library uses the bandersnatch curve & ring parameters specified in the [Graypaper](https://graypaper.com/). The following capabilities are supported:

- verifying an IETF signature
- generating a ring commitment
- verifying a ring signature
- calculating the hash of a vrf output point

For a complete API reference, please visit our [docs site](https://zero-trust-collective.github.io/jam-vrf/jam_vrf.html). For live examples, see our [python tests](./python/tests/)