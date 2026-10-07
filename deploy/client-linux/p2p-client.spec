# M4-03 rpm 打包规格（NFR-33、08 §3.2；布局与 deb 同口径，实机构建归 M4-10 环境依赖——
# 公网服务器为 Debian 无 rpmbuild，装 rpmbuild 环境属系统变更待用户确认）。
# 构建（任一 rpm 系发行版）：产物源上传后——
#   rpmbuild 须标准目录树，简版用 rpmbuild --buildroot 直出：
#   1) rpmbuild -bb --buildroot <空目录> --define "_topdir $PWD/rpmbuild" p2p-client.spec
#   （或装齐 rpm-build+rpmdevtools 后 rpmbuild -bb p2p-client.spec）
# 布局：/usr/lib/p2p-client/{p2p-client,wwwroot,staticwebassets.endpoints.json}+
#       /usr/bin/p2p-client 符号链接+/lib/systemd/system/p2p-client.service+/etc/p2p-client(0700,%post 建)
# 卸载语义与 deb 差异：rpm 无 purge 两段——erase 即清状态目录（升级 $1>0 保留）。

%define pkgversion 1.0.0

Name:           p2p-client
Version:        %{pkgversion}
Release:        1%{?dist}
Summary:        P2P virtual NIC port-mapping tunnel client
License:        Proprietary
URL:            https://example.invalid/p2p
Source0:        client-linux.tar.gz
BuildArch:      noarch
ExclusiveArch:  x86_64
Requires:       iproute2
%description
Client daemon with local web console on http://127.0.0.1:7100 (loopback only).
Program dir /usr/lib/p2p-client, state dir /etc/p2p-client (0700).

%prep
%setup -q -n client-linux || true

%build
# 预构建产物（dotnet publish 单文件自包含），无编译步骤

%install
rm -rf %{buildroot}
install -D -m 0755 p2p-client %{buildroot}/usr/lib/p2p-client/p2p-client
install -D -m 0644 p2p-client.staticwebassets.endpoints.json \
  %{buildroot}/usr/lib/p2p-client/p2p-client.staticwebassets.endpoints.json 2>/dev/null ||:
mkdir -p %{buildroot}/usr/lib/p2p-client/wwwroot
cp -r wwwroot/. %{buildroot}/usr/lib/p2p-client/wwwroot/
install -d %{buildroot}/usr/bin
ln -s ../lib/p2p-client/p2p-client %{buildroot}/usr/bin/p2p-client
install -D -m 0644 %{_sourcedir}/p2p-client.service %{buildroot}/lib/systemd/system/p2p-client.service

%files
/usr/lib/p2p-client/
/usr/bin/p2p-client
/lib/systemd/system/p2p-client.service
%license %{_docdir}/*

%post
install -d -m 0700 /etc/p2p-client
chmod 0700 /etc/p2p-client 2>/dev/null || :
systemctl daemon-reload >/dev/null 2>&1 || :
systemctl enable p2p-client.service >/dev/null 2>&1 || :
# 首装不 start（须向导注册）；升级（$1>1）服务在跑则重启切版
if [ "$1" -gt 1 ] && systemctl is-active --quiet p2p-client.service 2>/dev/null; then
  systemctl restart p2p-client.service || :
fi

%preun
# $1=0 擦除：停服务+取消自启；升级（$1=1）不停（POSIX inode 替换）
if [ "$1" -eq 0 ]; then
  systemctl stop p2p-client.service >/dev/null 2>&1 || :
  systemctl disable p2p-client.service >/dev/null 2>&1 || :
fi

%postun
systemctl daemon-reload >/dev/null 2>&1 || :
# $1=0 擦除：清状态目录（rpm 无 purge 两段语义）
if [ "$1" -eq 0 ]; then
  rm -rf /etc/p2p-client
fi

%changelog
* Wed Oct 07 2026 P2P <admin@p2p.invalid> - 1.0.0-1
- Initial package (M4-03, NFR-33)
