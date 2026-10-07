// M4-01 宿主版本信息（08 §1）：src/Directory.Build.props 统一注入 Version=1.0.0 +
// ThisAssembly.Metadata（GitCommit/BuildDate）——客户端 /api/system/state 与服务端
// 仪表盘的版本展示共用；本程序集（P2P.Core）与两宿主工程同受注入，值一致。
using System.Reflection;

namespace P2P.Core;

/// <summary>宿主版本与构建元数据（只读快照，进程内恒定）。</summary>
public static class AppVersion
{
    private static readonly Assembly Self = typeof(AppVersion).Assembly;

    /// <summary>语义版本三段式（如 1.0.0），与 protocolVersion 独立演进（08 §1）。</summary>
    public static string Version { get; } = Self.GetName().Version?.ToString(3) ?? "0.0.0";

    /// <summary>构建时 git 短哈希（源码包构建容错 "unknown"）。</summary>
    public static string Commit { get; } = ReadMetadata("GitCommit") ?? "unknown";

    /// <summary>构建时间（SOURCE_DATE_EPOCH 存在时为其值，否则 UTC ISO 时间）。</summary>
    public static string BuildDate { get; } = ReadMetadata("BuildDate") ?? "unknown";

    private static string? ReadMetadata(string key) =>
        Self.GetCustomAttributes<AssemblyMetadataAttribute>()
            .FirstOrDefault(m => string.Equals(m.Key, key, StringComparison.Ordinal))
            ?.Value;
}
