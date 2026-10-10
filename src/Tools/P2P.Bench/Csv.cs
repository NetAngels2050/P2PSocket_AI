// M4-05 CSV 写出与分布统计（NFR-14 建立/延迟 min/p50/p95/max 口径）。
using System.Text;

namespace P2P.Bench;

/// <summary>CSV 行集：按列头累积行，落盘一次（out/benchmark/*.csv）。</summary>
internal sealed class Csv(string name, params string[] columns)
{
    private readonly List<object[]> _rows = [];

    public string Name { get; } = name;

    public void Row(params object[] cells) => _rows.Add(cells);

    public int RowCount => _rows.Count;

    /// <summary>回读（summary 统计）：行以落盘同口径格式化（double=Invariant 0.###）。</summary>
    public List<string[]> RowsAsString() => _rows.Select(r => r.Select(Escape).ToArray()).ToList();

    public async Task WriteAsync(string dir)
    {
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, Name);
        await using var w = new StreamWriter(path, append: false, new UTF8Encoding(false));
        await w.WriteLineAsync(string.Join(",", columns.Select(Escape)));
        foreach (var row in _rows)
            await w.WriteLineAsync(string.Join(",", row.Select(Escape)));
    }

    private static string Escape(object cell)
    {
        var s = cell switch
        {
            double d => d.ToString("0.###", System.Globalization.CultureInfo.InvariantCulture),
            float f => f.ToString("0.###", System.Globalization.CultureInfo.InvariantCulture),
            _ => cell.ToString() ?? "",
        };
        return s.Contains(',') || s.Contains('"') || s.Contains('\n')
            ? $"\"{s.Replace("\"", "\"\"")}\"" : s;
    }
}

/// <summary>时长样本分布（NFR-14：min/p50/p95/max + 均值；p 线性插值口径）。</summary>
internal sealed class DurationStats(List<long> samplesMs)
{
    public int Count => samplesMs.Count;
    public long Min => samplesMs.Min();
    public long Max => samplesMs.Max();
    public double Avg => samplesMs.Average();

    public long P50 => Percentile(50);

    public long P95 => Percentile(95);

    public long Percentile(int p)
    {
        var sorted = samplesMs.OrderBy(x => x).ToList();
        var idx = (int)Math.Ceiling(p / 100.0 * sorted.Count) - 1;
        return sorted[Math.Clamp(idx, 0, sorted.Count - 1)];
    }
}
