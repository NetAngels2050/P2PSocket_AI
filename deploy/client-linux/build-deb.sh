#!/bin/sh
# M4-03 deb 构建脚本（NFR-33、08 §3.2）：组装 debian 安装树 + dpkg-deb -b。
# 在 Debian/Ubuntu（公网服务器）上执行；产物源=out/client-linux（package.sh client-linux 目标产出，
# 本机构建后上传：tar 解包或 scp -r out/client-linux root@<server>:/tmp/）。
# 用法：sh deploy/client-linux/build-deb.sh [版本号]   缺省从 src/Directory.Build.props 提取
# 布局（对 03 §5 实现口径的修正说明：Linux 数据目录=代码硬编码 /etc/p2p-client 单目录——
#   清单行起草时的 /var/lib/p2p-client 拆分不存在，exe+wwwroot 须同目录[MapStaticAssets
#   按 AppContext.BaseDirectory 解析]故主程序位 /usr/lib/p2p-client、/usr/bin 放符号链接）：
#   /usr/lib/p2p-client/{p2p-client,wwwroot/,staticwebassets.endpoints.json}
#   /usr/bin/p2p-client → 符号链接（CLI：p2p-client --uninstall 等）
#   /lib/systemd/system/p2p-client.service（postinst 装载）
#   /etc/p2p-client/（0700，postinst 创建——运行时 state.json/凭据/日志，purge 清）
set -e
cd "$(dirname "$0")/../.."

VERSION="${1:-$(sed -n 's/.*<Version>\(.*\)<\/Version>.*/\1/p' src/Directory.Build.props | head -1)}"
[ -n "$VERSION" ] || { echo "版本号缺失（src/Directory.Build.props 无 <Version> 且未传参）"; exit 1; }

SRC=out/client-linux
[ -f "$SRC/p2p-client" ] || { echo "产物缺失：$SRC/p2p-client（先在构建机跑 sh build/package.sh client-linux 并上传）"; exit 1; }

STAGE=deploy/client-linux/build/p2p-client
rm -rf deploy/client-linux/build
mkdir -p "$STAGE/DEBIAN" "$STAGE/usr/lib/p2p-client" "$STAGE/usr/bin" \
  "$STAGE/lib/systemd/system"

# 产物：单文件二进制+SPA 清单+wwwroot（pdb 调试符号不分发）
cp "$SRC/p2p-client" "$STAGE/usr/lib/p2p-client/"
cp "$SRC/p2p-client.staticwebassets.endpoints.json" "$STAGE/usr/lib/p2p-client/" 2>/dev/null \
  || echo "警告：staticwebassets.endpoints.json 缺失（SPA 静态托管将退化为仅 API）"
cp -r "$SRC/wwwroot" "$STAGE/usr/lib/p2p-client/"
rm -f "$STAGE/usr/lib/p2p-client/wwwroot"/*.pdb 2>/dev/null || true
ln -s ../lib/p2p-client/p2p-client "$STAGE/usr/bin/p2p-client"

# 控制脚本与单元（模板版本号注入）
cp -r deploy/client-linux/debian/DEBIAN/. "$STAGE/DEBIAN/"
sed -i "s/@VERSION@/$VERSION/" "$STAGE/DEBIAN/control"
cp deploy/client-linux/debian/lib/systemd/system/p2p-client.service "$STAGE/lib/systemd/system/"
chmod 0755 "$STAGE/DEBIAN/postinst" "$STAGE/DEBIAN/prerm" "$STAGE/DEBIAN/postrm"

OUT="out/p2p-client_$VERSION-1_amd64.deb"
dpkg-deb -b --root-owner-group "$STAGE" "$OUT"
echo "==> 构建完成：$OUT"
echo "    清单校验：dpkg-deb -c $OUT"
echo "    信息核对：dpkg-deb -I $OUT"
