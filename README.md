# pyvrfs

Python bindings for the [ark-ec-vrfs library](https://github.com/davxy/ark-ec-vrfs/tree/main). Currently the bindings are tightly coupled with trams needs, but this library will be expanded to align more closely with the rust vrfs lib soon.

## Contributing

to build, run `make develop`. To test, run `make test`

### Pushing Changes to tram

When attempting to propogate updates from the pyvrfs library to tram, sometimes tram requires a fresh install of the pyvrfs lib in order to pick up the changes. Once we settle on a project versioning strategy, incrementing the pyvrfs lib version should also be a viable approach for this issue.
