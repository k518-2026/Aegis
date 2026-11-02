using System;
using System.Collections.Generic;

namespace Aegis.Models
{
    /// <summary>脅威レベル</summary>
    public enum ThreatLevel
    {
        Clean = 0,
        Info = 1,
        Low = 2,
        Medium = 3,
        High = 4,
        Critical = 5
    }

    public static class ThreatLevelEx
    {
        public static string ToJapanese(this ThreatLevel l)
        {
            switch (l)
            {
                case ThreatLevel.Critical: return "危険度：最大";
                case ThreatLevel.High: return "危険度：高";
                case ThreatLevel.Medium: return "危険度：中";
                case ThreatLevel.Low: return "危険度：低";
                case ThreatLevel.Info: return "参考情報";
                default: return "問題なし";
            }
        }

        public static string ToColor(this ThreatLevel l)
        {
            switch (l)
            {
                case ThreatLevel.Critical: return "#FFFF4D6D";
                case ThreatLevel.High: return "#FFF3506A";
                case ThreatLevel.Medium: return "#FFF5A524";
                case ThreatLevel.Low: return "#FFE6C34A";
                case ThreatLevel.Info: return "#FF7FB8E6";
                default: return "#FF3DD68C";
            }
        }
    }

    /// <summary>検出項目（1ファイル1ルールにつき1件）</summary>
    public class Detection
    {
        public string FilePath { get; set; } = "";
        public string FileName { get; set; } = "";
        public string Sha256 { get; set; } = "";
        public long Size { get; set; }
        public string RuleId { get; set; } = "";
        public string RuleName { get; set; } = "";
        public string Description { get; set; } = "";
        public ThreatLevel Level { get; set; } = ThreatLevel.Info;
        public DateTime DetectedAt { get; set; } = DateTime.Now;

        public string LevelText { get { return Level.ToJapanese(); } }
        public string LevelColor { get { return Level.ToColor(); } }
        public string SizeText { get { return Util.FormatSize(Size); } }
        public string TimeText { get { return DetectedAt.ToString("HH:mm:ss"); } }
    }

    /// <summary>スキャン進捗</summary>
    public class ScanProgress
    {
        public int FilesScanned { get; set; }
        public int FilesTotal { get; set; }
        public int DetectionCount { get; set; }
        public string CurrentFile { get; set; } = "";
        public double Percent
        {
            get { return FilesTotal <= 0 ? 0 : Math.Min(100.0, FilesScanned * 100.0 / FilesTotal); }
        }
    }

    /// <summary>スキャン結果サマリ</summary>
    public class ScanSummary
    {
        public DateTime StartedAt { get; set; }
        public DateTime FinishedAt { get; set; }
        public int FilesScanned { get; set; }
        public int FilesSkipped { get; set; }
        public long BytesScanned { get; set; }
        public List<Detection> Detections { get; set; } = new List<Detection>();
        public bool Canceled { get; set; }
        public TimeSpan Elapsed { get { return FinishedAt - StartedAt; } }
    }

    /// <summary>隔離済みファイル</summary>
    public class QuarantineItem
    {
        public string Id { get; set; } = "";
        public string OriginalPath { get; set; } = "";
        public string FileName { get; set; } = "";
        public string Sha256 { get; set; } = "";
        public long Size { get; set; }
        public string RuleName { get; set; } = "";
        public string Level { get; set; } = "";
        public DateTime QuarantinedAt { get; set; }

        public string SizeText { get { return Util.FormatSize(Size); } }
        public string DateText { get { return QuarantinedAt.ToString("yyyy/MM/dd HH:mm"); } }
    }

    /// <summary>フィッシング判定の個別根拠</summary>
    public class UrlSignal
    {
        public string Name { get; set; } = "";
        public string Detail { get; set; } = "";
        public int Score { get; set; }
        public string ScoreText { get { return Score > 0 ? "+" + Score : Score.ToString(); } }
        public string Color
        {
            get
            {
                if (Score >= 25) return "#FFF3506A";
                if (Score >= 10) return "#FFF5A524";
                if (Score > 0) return "#FFE6C34A";
                return "#FF3DD68C";
            }
        }
    }

    /// <summary>URL判定結果</summary>
    public class UrlVerdict
    {
        public string Url { get; set; } = "";
        public string Host { get; set; } = "";
        public int Score { get; set; }
        public List<UrlSignal> Signals { get; set; } = new List<UrlSignal>();

        public string Judgement
        {
            get
            {
                if (Score >= 75) return "極めて危険（フィッシングの疑いが濃厚）";
                if (Score >= 50) return "危険（開かないでください）";
                if (Score >= 25) return "要注意（不審な特徴あり）";
                if (Score >= 10) return "軽微な注意点あり";
                return "明らかな危険信号は見つかりません";
            }
        }

        public string JudgementColor
        {
            get
            {
                if (Score >= 50) return "#FFF3506A";
                if (Score >= 25) return "#FFF5A524";
                if (Score >= 10) return "#FFE6C34A";
                return "#FF3DD68C";
            }
        }
    }

    public enum CheckStatus { Ok, Warn, Danger, Unknown }

    /// <summary>システム診断の1項目</summary>
    public class SystemCheckItem
    {
        public string Category { get; set; } = "";
        public string Name { get; set; } = "";
        public CheckStatus Status { get; set; } = CheckStatus.Unknown;
        public string Detail { get; set; } = "";
        public string Advice { get; set; } = "";

        public string StatusText
        {
            get
            {
                switch (Status)
                {
                    case CheckStatus.Ok: return "良好";
                    case CheckStatus.Warn: return "注意";
                    case CheckStatus.Danger: return "危険";
                    default: return "不明";
                }
            }
        }

        public string StatusColor
        {
            get
            {
                switch (Status)
                {
                    case CheckStatus.Ok: return "#FF3DD68C";
                    case CheckStatus.Warn: return "#FFF5A524";
                    case CheckStatus.Danger: return "#FFF3506A";
                    default: return "#FF9AA5B5";
                }
            }
        }
    }

    /// <summary>自動起動エントリ</summary>
    public class AutorunItem
    {
        public string Source { get; set; } = "";
        public string Name { get; set; } = "";
        public string Command { get; set; } = "";
        public string ResolvedPath { get; set; } = "";
        public string Signer { get; set; } = "";
        public ThreatLevel Level { get; set; } = ThreatLevel.Info;
        public string Note { get; set; } = "";

        public string LevelText { get { return Level >= ThreatLevel.Medium ? "要確認" : "通常"; } }
        public string LevelColor { get { return Level.ToColor(); } }
    }

    public static class Util
    {
        public static string FormatSize(long bytes)
        {
            string[] u = { "B", "KB", "MB", "GB", "TB" };
            double v = bytes;
            int i = 0;
            while (v >= 1024 && i < u.Length - 1) { v /= 1024; i++; }
            return (i == 0 ? v.ToString("0") : v.ToString("0.##")) + " " + u[i];
        }
    }
}
