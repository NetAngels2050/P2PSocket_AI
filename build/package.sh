#!/bin/sh
# 打包脚本（08 §2⑤，M4-01）：前端构建 → dotnet publish 单文件自包含 → out/ 产物目录（+Linux tar.gz 归档）。
# 用法：sh build/package.sh [client-win|client-linux|server|all]   缺省 all
# 依赖：dotnet SDK 10、node ≥20、pnpm（corepack enable pnpm）。
# Windows 客户端另需 Wintun.dll（官方 0.14.1 amd64，wintun.net；放 out/wintun/Wintun.dll，
#   脚本自动拷入产物；未放置则警告提示手工分发——08 §3.1 Wintun 走程序目录分发不内嵌）。
# publish 参数=部署文档验证过的口径（PublishSingleFile+SelfContained；M1-37/M3-18 实机轮沿用）。
set -e
cd "$(dirname "$0")/.."

TARGET="${1:-all}"

# 版本号：src/Directory.Build.props 单一事实源（M4-01 注入，git 短哈希经 ThisAssembly.Metadata 进 exe）
VERSION=$(sed -n 's/.*<Version>\(.*\)<\/Version>.*/\1/p' src/Directory.Build.props | head -1)
[ -n "$VERSION" ] || VERSION="0.0.0"

web_build() { # $*=pnpm --filter 包名
  echo "==> 前端构建 $*"
  pnpm -C web "$@" build
}

publish() { # $1=项目路径 $2=RID $3=产物目录名
  echo "==> publish $1 ($2) → out/$3"
  rm -rf "out/$3"
  dotnet publish "$1" -c Release -r "$2" \
    -p:PublishSingleFile=true -p:SelfContained=true -o "out/$3"
  # 产物校验：可执行体 + 前端入口（wwwroot 由 SDK 自 src 宿主目录拷入）
  test -f "out/$3/p2p-client" || test -f "out/$3/p2p-client.exe" || test -f "out/$3/p2p-server" \
    || { echo "产物校验失败：out/$3 无可执行体"; exit 1; }
  test -f "out/$3/wwwroot/index.html" || { echo "产物校验失败：out/$3/wwwroot/index.html 缺失（前端未构建？）"; exit 1; }
}

archive() { # $1=产物目录名（Linux 分发形态 tar.gz）
  echo "==> 归档 out/$1 → out/p2p-$1-v$VERSION.tar.gz"
  tar -czf "out/p2p-$1-v$VERSION.tar.gz" -C "out/$1" .
}

want() { echo "$TARGET" | grep -qw "$1"; } # all 含全部目标

STATUS=""
run_client_win() {
  web_build --filter @p2p/client-app
  publish src/P2P.Client win-x64 client-win
  if [ -f out/wintun/Wintun.dll ]; then
    cp out/wintun/Wintun.dll out/client-win/
    echo "==> Wintun.dll 已拷入 out/client-win"
  else
    echo "警告：out/wintun/Wintun.dll 不存在——产物未含 Wintun 驱动库，分发前须手工放置（08 §3.1）"
  fi
  STATUS="$STATUS client-win(v$VERSION)"
}
run_client_linux() {
  web_build --filter @p2p/client-app
  publish src/P2P.Client linux-x64 client-linux
  archive client-linux
  STATUS="$STATUS client-linux(v$VERSION)"
}
run_server() {
  web_build --filter @p2p/server-app
  publish src/P2P.Server linux-x64 server
  archive server
  STATUS="$STATUS server(v$VERSION)"
}
run_win_setup() { # M4-02：Inno Setup 安装包（依赖 client-win 产物；ISCC 缺失=环境依赖如实标注）
  run_client_win
  ISCC="/c/Program Files (x86)/Inno Setup 6/ISCC.exe"
  if [ ! -f "$ISCC" ]; then
    ISCC="/c/Program Files/Inno Setup 6/ISCC.exe"
  fi
  if [ ! -f "$ISCC" ]; then # winget 用户级安装位（JRSoftware.InnoSetup 默认）
    ISCC="$LOCALAPPDATA/Programs/Inno Setup 6/ISCC.exe"
  fi
  if [ -f "$ISCC" ]; then
    echo "==> ISCC 编译 P2PClient.iss → out/P2PClient-Setup-$VERSION-x64.exe"
    "$ISCC" //DPkgVersion="$VERSION" deploy/client/win/P2PClient.iss || { echo "ISCC 编译失败"; exit 1; }
    test -f "out/P2PClient-Setup-$VERSION-x64.exe" \
      || { echo "产物校验失败：out/P2PClient-Setup-$VERSION-x64.exe 缺失"; exit 1; }
    STATUS="$STATUS win-setup(v$VERSION)"
  else
    echo "警告：ISCC.exe 不存在（Inno Setup 6 未安装，winget install JRSoftware.InnoSetup）——"
    echo "      跳过安装包编译（环境依赖，M4-02 清单 §8.2）；deploy/client/win/P2PClient.iss 为交付物"
    STATUS="$STATUS win-setup(跳过：ISCC 未装)"
  fi
}

case "$TARGET" in
  client-win) run_client_win ;;
  client-linux) run_client_linux ;;
  server) run_server ;;
  win-setup) run_win_setup ;;
  all) run_client_win; run_client_linux; run_server ;;
  *) echo "未知目标：$TARGET（支持 client-win|client-linux|server|win-setup|all）"; exit 1 ;;
esac

echo "==> 打包完成：$STATUS"
