using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Aegis.Models;

namespace Aegis.Services
{
    public static class ReportExporter
    {
        public static void ExportDetectionsCsv(string path, IEnumerable<Detection> items)
        {
            var sb = new StringBuilder();
            sb.AppendLine("検出日時,危険度,ルール,ファイル名,パス,サイズ,SHA-256,説明");
            foreach (var d in items)
            {
                sb.AppendLine(string.Join(",",
                    Q(d.DetectedAt.ToString("yyyy/MM/dd HH:mm:ss")),
                    Q(d.LevelText), Q(d.RuleName), Q(d.FileName), Q(d.FilePath),
                    Q(d.Size.ToString()), Q(d.Sha256), Q(d.Description)));
            }
            File.WriteAllText(path, sb.ToString(), new UTF8Encoding(true));
        }

        public static void ExportScanHtml(string path, ScanSummary summary, List<SystemCheckItem> checks)
        {
            var sb = new StringBuilder();
            sb.AppendLine("<!DOCTYPE html><html lang=\"ja\"><head><meta charset=\"utf-8\">");
            sb.AppendLine("<title>Aegis セキュリティレポート</title><style>");
            sb.AppendLine("body{font-family:'Yu Gothic UI',Meiryo,sans-serif;background:#13161c;color:#e8ecf3;margin:0;padding:32px;}");
            sb.AppendLine("h1{font-size:22px;border-bottom:2px solid #3da9fc;padding-bottom:8px;}");
            sb.AppendLine("h2{font-size:17px;margin-top:32px;color:#3da9fc;}");
            sb.AppendLine("table{border-collapse:collapse;width:100%;margin-top:12px;font-size:13px;}");
            sb.AppendLine("th,td{border:1px solid #2e3542;padding:7px 10px;text-align:left;vertical-align:top;}");
            sb.AppendLine("th{background:#232833;}tr:nth-child(even) td{background:#171b23;}");
            sb.AppendLine(".ok{color:#3dd68c}.warn{color:#f5a524}.ng{color:#f3506a}.mute{color:#9aa5b5}");
            sb.AppendLine(".sum{background:#1b1f27;border:1px solid #2e3542;border-radius:10px;padding:16px;margin-top:16px;}");
            sb.AppendLine("</style></head><body>");

            sb.AppendLine("<h1>Aegis セキュリティレポート</h1>");
            sb.AppendLine("<p class=\"mute\">作成日時: " + DateTime.Now.ToString("yyyy年M月d日 HH:mm") +
                          " / コンピューター名: " + Esc(Environment.MachineName) + "</p>");

            if (summary != null)
            {
                sb.AppendLine("<div class=\"sum\">");
                sb.AppendLine("<b>スキャン結果</b><br>");
                sb.AppendLine("検査ファイル数: " + summary.FilesScanned + " 件 / ");
                sb.AppendLine("スキップ: " + summary.FilesSkipped + " 件 / ");
                sb.AppendLine("検出: <span class=\"" + (summary.Detections.Count > 0 ? "ng" : "ok") + "\">" +
                              summary.Detections.Count + " 件</span> / ");
                sb.AppendLine("所要時間: " + summary.Elapsed.ToString(@"hh\:mm\:ss"));
                sb.AppendLine("</div>");

                sb.AppendLine("<h2>検出項目</h2>");
                if (summary.Detections.Count == 0)
                {
                    sb.AppendLine("<p class=\"ok\">問題は見つかりませんでした。</p>");
                }
                else
                {
                    sb.AppendLine("<table><tr><th>危険度</th><th>ルール</th><th>ファイル</th><th>説明</th></tr>");
                    foreach (var d in summary.Detections)
                    {
                        string cls = d.Level >= ThreatLevel.High ? "ng" : d.Level >= ThreatLevel.Medium ? "warn" : "mute";
                        sb.AppendLine("<tr><td class=\"" + cls + "\">" + Esc(d.LevelText) + "</td><td>" +
                                      Esc(d.RuleName) + "</td><td>" + Esc(d.FilePath) + "</td><td>" +
                                      Esc(d.Description).Replace("\n", "<br>") + "</td></tr>");
                    }
                    sb.AppendLine("</table>");
                }
            }

            if (checks != null && checks.Count > 0)
            {
                sb.AppendLine("<h2>システム診断</h2>");
                sb.AppendLine("<table><tr><th>分類</th><th>項目</th><th>状態</th><th>内容</th><th>推奨対処</th></tr>");
                foreach (var c in checks)
                {
                    string cls = c.Status == CheckStatus.Ok ? "ok" :
                                 c.Status == CheckStatus.Warn ? "warn" :
                                 c.Status == CheckStatus.Danger ? "ng" : "mute";
                    sb.AppendLine("<tr><td>" + Esc(c.Category) + "</td><td>" + Esc(c.Name) +
                                  "</td><td class=\"" + cls + "\">" + Esc(c.StatusText) + "</td><td>" +
                                  Esc(c.Detail).Replace("\n", "<br>") + "</td><td>" + Esc(c.Advice) + "</td></tr>");
                }
                sb.AppendLine("</table>");
            }

            sb.AppendLine("<p class=\"mute\" style=\"margin-top:32px;font-size:12px;\">" +
                          "このレポートは Aegis による簡易診断の結果です。総合的なウイルス対策ソフトの代わりにはなりません。</p>");
            sb.AppendLine("</body></html>");

            File.WriteAllText(path, sb.ToString(), new UTF8Encoding(true));
        }

        private static string Q(string s)
        {
            s = s ?? "";
            return "\"" + s.Replace("\"", "\"\"").Replace("\r", " ").Replace("\n", " ") + "\"";
        }

        private static string Esc(string s)
        {
            s = s ?? "";
            return s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;");
        }
    }
}
