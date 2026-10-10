// M4-05 P0 修复配套（02 §2.4 seq 严格递增）：
// 出站消息 seq 必须与"写入发送通道"同点分配——多线程并发发送时，调用方构造时刻分配的 seq
// 与实际写线序可能交错（分配序≠写线序），触发对端 seq_regression 断连。
// 本工具按主构造函数参数名回填 Seq/TimestampMs 重建消息（全部 PCP 消息为 positional record，
// Key(0)=Seq、Key(1)=TimestampMs），供发送临界区内重盖。构造器反射按类型缓存。
using System.Collections.Concurrent;
using System.Reflection;

namespace P2P.Core.Protocol;

/// <summary>消息头重盖（5005 重试与服务端发送队列入队前重盖共用）。</summary>
public static class MessageRebuilder
{
    private sealed record CtorCache(ConstructorInfo Ctor, ParameterInfo[] Params, Func<object, object?>[] Getters);

    private static readonly ConcurrentDictionary<Type, CtorCache> Cache = new();

    /// <typeparam name="T">泛型保型（静态类型随调用方消息传入）：重建结果供
    /// <c>PcpCodec.Encode&lt;T&gt;</c> 等泛型编码按具体类型序列化（接口静态类型 MessagePack 不可序列化）。</typeparam>
    public static T WithHeader<T>(T message, uint seq, ulong timestampMs) where T : class, IPcpMessage
    {
        var cache = Cache.GetOrAdd(message.GetType(), static t =>
        {
            var ctor = t.GetConstructors().Single();
            var parameters = ctor.GetParameters();
            var getters = new Func<object, object?>[parameters.Length];
            for (var i = 0; i < parameters.Length; i++)
                getters[i] = parameters[i].Name is "Seq" or "TimestampMs"
                    ? null! // 头两参数由下方 switch 回填，不走 getter（恒不调用）
                    : BuildGetter(t, parameters[i].Name!);
            return new CtorCache(ctor, parameters, getters);
        });
        var args = new object?[cache.Params.Length];
        for (var i = 0; i < cache.Params.Length; i++)
        {
            args[i] = cache.Params[i].Name switch
            {
                "Seq" => seq,
                "TimestampMs" => timestampMs,
                _ => cache.Getters[i]!(message),
            };
        }
        return (T)cache.Ctor.Invoke(args);
    }

    private static Func<object, object?> BuildGetter(Type type, string name)
    {
        var prop = type.GetProperty(name) ?? throw new InvalidOperationException(
            $"{type.Name} 缺少构造参数 {name} 的同名属性（positional record 约定）");
        var method = prop.GetGetMethod()!;
        return obj => method.Invoke(obj, null);
    }
}
