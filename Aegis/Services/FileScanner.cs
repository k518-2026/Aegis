using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Aegis.Models;

namespace Aegis.Services
{
    public class ScanOptions
    {
        /// <summary>ハッシュ計算の対象にする最大サイズ</summary>
        public long MaxHashSize { get; set; } = 256L * 1024 * 1024;
        public bool UseHeuristics { get; set; } = true;
        public bool DeepInspection { get; set; } = true;
        public bool IncludeSubFolders { get; set; } = true;
        /// <summary>参考情報レベルの検出も一覧に載せる</summary>
        public bool ReportInfoLevel { get; set; } = false;
    }

    public class FileScanner
    {
        private readonly SignatureDatabase _db;
        private readonly HeuristicEngine _heur = new HeuristicEngine();

        private static readonly string[] SkipDirNames =
        {
            "$Recycle.Bin", "System Volume Information", "WinSxS", "Windows Defender",
            "DriverStore", "node_modules", ".git"
        };

        public FileScanner(SignatureDatabase db)
        {
            _db = db;
        }

        public Task<ScanSummary> ScanAsync(IEnumerable<string> targets, ScanOptions opt,
            IProgress<ScanProgress> progress, Action<Detection> onDetection, CancellationToken token)
        {
            return Task.Run(() => Scan(targets, opt, progress, onDetection, token), token);
        }

        private ScanSummary Scan(IEnumerable<string> targets, ScanOptions opt,
            IProgress<ScanProgress> progress, Action<Detection> onDetection, CancellationToken token)
        {
            var summary = new ScanSummary { StartedAt = DateTime.Now };
            _heur.DeepInspection = opt.DeepInspection;

            List<string> files = new List<string>();
            foreach (string t in targets)
            {
                if (token.IsCancellationRequested) break;
                try
                {
                    if (File.Exists(t)) files.Add(t);
                    else if (Directory.Exists(t)) CollectFiles(t, opt.IncludeSubFolders, files, token);
                }
                catch (Exception ex)
                {
                    AppLog.Warn("列挙に失敗: " + t + " / " + ex.Message);
                }
            }

            var prog = new ScanProgress { FilesTotal = files.Count };

            foreach (string path in files)
            {
                if (token.IsCancellationRequested) { summary.Canceled = true; break; }

                prog.FilesScanned++;
                prog.CurrentFile = path;

                try
                {
                    var fi = new FileInfo(path);
                    if (!fi.Exists) { summary.FilesSkipped++; continue; }

                    var found = new List<Detection>();

                    // 1) ハッシュ定義との照合
                    string hash = null;
                    if (fi.Length <= opt.MaxHashSize)
                    {
                        hash = FileUtil.Sha256(path);
                        SignatureEntry entry;
                        if (hash != null && _db.TryMatch(hash, out entry))
                        {
                            found.Add(new Detection
                            {
                                FilePath = path,
                                FileName = fi.Name,
                                Sha256 = hash,
                                Size = fi.Length,
                                RuleId = "SIG",
                                RuleName = "定義ファイル一致: " + entry.Name,
                                Level = SignatureDatabase.ParseLevel(entry.Level),
                                Description = string.IsNullOrEmpty(entry.Note)
                                    ? "既知の脅威としてハッシュ定義に登録されています。"
                                    : entry.Note
                            });
                        }
                    }
                    else
                    {
                        summary.FilesSkipped++;
                    }

                    // 2) ヒューリスティック検査
                    if (opt.UseHeuristics)
                    {
                        foreach (var d in _heur.Inspect(fi))
                        {
                            d.Sha256 = hash ?? "";
                            found.Add(d);
                        }
                    }

                    summary.BytesScanned += fi.Length;
                    summary.FilesScanned++;

                    foreach (var d in found)
                    {
                        if (!opt.ReportInfoLevel && d.Level <= ThreatLevel.Info) continue;
                        summary.Detections.Add(d);
                        prog.DetectionCount++;
                        if (onDetection != null) onDetection(d);
                    }
                }
                catch (UnauthorizedAccessException)
                {
                    summary.FilesSkipped++;
                }
                catch (IOException)
                {
                    summary.FilesSkipped++;
                }
                catch (Exception ex)
                {
                    summary.FilesSkipped++;
                    AppLog.Warn("検査に失敗: " + path + " / " + ex.Message);
                }

                if (progress != null && (prog.FilesScanned % 15 == 0 || prog.FilesScanned == files.Count))
                {
                    progress.Report(new ScanProgress
                    {
                        FilesScanned = prog.FilesScanned,
                        FilesTotal = prog.FilesTotal,
                        DetectionCount = prog.DetectionCount,
                        CurrentFile = prog.CurrentFile
                    });
                }
            }

            summary.FinishedAt = DateTime.Now;
            return summary;
        }

        private static void CollectFiles(string dir, bool recursive, List<string> sink, CancellationToken token)
        {
            if (token.IsCancellationRequested) return;

            try
            {
                foreach (string f in Directory.EnumerateFiles(dir))
                {
                    if (token.IsCancellationRequested) return;
                    sink.Add(f);
                }
            }
            catch { /* アクセス不可のフォルダは飛ばす */ }

            if (!recursive) return;

            try
            {
                foreach (string sub in Directory.EnumerateDirectories(dir))
                {
                    if (token.IsCancellationRequested) return;
                    string name = Path.GetFileName(sub);
                    bool skip = false;
                    foreach (string s in SkipDirNames)
                    {
                        if (string.Equals(name, s, StringComparison.OrdinalIgnoreCase)) { skip = true; break; }
                    }
                    if (skip) continue;

                    try
                    {
                        var di = new DirectoryInfo(sub);
                        if ((di.Attributes & FileAttributes.ReparsePoint) == FileAttributes.ReparsePoint) continue;
                    }
                    catch { continue; }

                    CollectFiles(sub, true, sink, token);
                }
            }
            catch { }
        }

        /// <summary>クイックスキャンの既定対象</summary>
        public static List<string> QuickScanTargets()
        {
            var list = new List<string>();
            void Add(string p) { if (!string.IsNullOrEmpty(p) && Directory.Exists(p)) list.Add(p); }

            Add(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory));
            Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"));
            Add(Path.GetTempPath());
            Add(Environment.GetFolderPath(Environment.SpecialFolder.Startup));
            Add(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup));
            Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Microsoft", "Windows", "Recent"));
            return list;
        }
    }
}
