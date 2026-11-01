# Maintainer: OpenNet contributors <opennet@example.invalid>
pkgname=opennet
pkgver=0.7.0
pkgrel=1
pkgdesc='Peer-to-peer network for distributed computing on a LAN'
arch=('x86_64' 'aarch64')
url='https://github.com/aiv-tmc/opennet'
license=('MPL-2.0')
depends=('gcc-libs' 'glibc')
makedepends=('cargo')
source=("$pkgname-$pkgver.tar.gz::$url/archive/v$pkgver.tar.gz")
sha256sums=('SKIP')   # run `updpkgsums`

prepare() {
    cd "$pkgname-$pkgver"
    cargo fetch --locked --target "$(rustc -vV | sed -n 's/host: //p')"
}

build() {
    cd "$pkgname-$pkgver"
    cargo build --release --locked
}

package() {
    cd "$pkgname-$pkgver"
    install -Dm755 target/release/opennetd  "$pkgdir/usr/bin/opennetd"
    install -Dm755 target/release/opennetctl "$pkgdir/usr/bin/opennetctl"
    install -Dm644 init/opennetd.service "$pkgdir/usr/lib/systemd/system/opennetd.service"
    install -Dm644 opennet.sysusers "$pkgdir/usr/lib/sysusers.d/opennet.conf"
    install -Dm644 opennet.tmpfiles "$pkgdir/usr/lib/tmpfiles.d/opennet.conf"
    install -Dm644 <(./target/release/opennetd --print-default-config) \
        "$pkgdir/etc/opennet/config.toml"
    install -Dm644 README.md "$pkgdir/usr/share/doc/$pkgname/README.md"
    install -Dm644 docs/architecture.md "$pkgdir/usr/share/doc/$pkgname/architecture.md"
    install -Dm644 docs/protocol.md "$pkgdir/usr/share/doc/$pkgname/protocol.md"
    install -Dm644 docs/swarm.md "$pkgdir/usr/share/doc/$pkgname/swarm.md"
    install -Dm644 docs/operations.md "$pkgdir/usr/share/doc/$pkgname/operations.md"
}
