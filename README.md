# Tailscale

This repository holds the patches
[Headwire](https://github.com/brofranks/headwire) applies to
[Tailscale](https://github.com/tailscale/tailscale): `upstream` holds the
current release and `patches/series` lists the patches in order. Each
`source/vX.Y.Z-headwire.N` branch contains the patched Go source, and the
`vX.Y.Z-headwire.N` tag marks the release commit.

## Usage

```sh
# Caution: deletes source/ first.
scripts/generate

# Publish a release.
fork=https://github.com/brofranks/tailscale.git
version=v1.104.7-headwire.3
git -C source push "$fork" "HEAD:refs/heads/source/$version"
# Wait for CI on source/$version to pass, then tag the tested commit.
git -C source tag -s "$version" -m "$version"
git -C source push "$fork" "refs/tags/$version"
```

## License

The patches include Tailscale code, Copyright (c) 2020 Tailscale Inc &
contributors, distributed under the
[BSD 3-Clause License](https://github.com/tailscale/tailscale/blob/main/LICENSE).
