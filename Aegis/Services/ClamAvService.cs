using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Aegis.Services
{
    /// <summary>見つかった ClamAV（clamscan.exe と freshclam.exe があるフォルダー）。</summary>
    public sealed class ClamAvEngine
    {
        public string Folder { get; set; }
        public string ClamScan { get { return Path.Combine(Folder, "clamscan.exe"); } }
        public string FreshClam { get { return Path.Combine(Folder, "freshclam.exe"); } }

        /// <summary>定義ファイルの置き場所。エンジンの隣に書けるならそこ、書けなければ %LOCALAPPDATA%\Aegis\clamav-db。</summary>
        public string DatabaseDir { get; set; }

        public bool HasDatabase
        {
            get
            {
                try
                {
                    // 公式の定義（.cvd/.cld/.cud）か、自分で作った定義（.hdb/.hsb/.ndb/.ldb）
                    string[] exts = { ".cvd", ".cld", ".cud", ".hdb", ".hsb", ".ndb", ".ldb" };
                    return Directory.Exists(DatabaseDir) &&
                           Directory.EnumerateFiles(DatabaseDir).Any(f => exts.Contains(Path.GetExtension(f).ToLowerInvariant()));
                }
                catch { return false; }
            }
        }
    }

    /// <summary>1 件の検出（clamscan の「パス: 名前 FOUND」）。</summary>
    public sealed class ClamAvHit
    {
        public string FilePath { get; set; }
        public string Signature { get; set; }
    }

    /// <summary>スキャンの結果。</summary>
    public sealed class ClamAvScanResult
    {
        public int FilesScanned { get; set; }
        public List<ClamAvHit> Hits { get; } = new List<ClamAvHit>();
        public List<string> Summary { get; } = new List<string>();
        public int ExitCode { get; set; }
        public bool Canceled { get; set; }
    }

    /// <summary>
    /// ClamAV（GPL-2.0、Cisco Systems）を外部プロセスとして呼び出す（旧 VirusScannerApp を統合、2026-11-02）。
    /// ClamAV 本体は Aegis.exe には入れない（DLL 約 70 MB・定義ファイル約 300 MB のため）。
    /// 探す順番: Aegis.exe の隣の ClamAV\ → ClamAV_Engine\ → 利用者が選んだ場所 → Program Files\ClamAV。
    /// </summary>
    public static class ClamAvService
    {
        private static string SettingsFile { get { return Path.Combine(AppLog.DataDir, "clamav-folder.txt"); } }

        public static ClamAvEngine Locate()
        {
            foreach (string dir in Candidates())
            {
                var e = TryFolder(dir);
                if (e != null) return e;
            }
            return null;
        }

        /// <summary>利用者が選んだフォルダー（clamscan.exe のあるところ）を使い、次回も覚えておく。</summary>
        public static ClamAvEngine Choose(string folder)
        {
            var e = TryFolder(folder);
            if (e == null) return null;
            try { File.WriteAllText(SettingsFile, folder, Encoding.UTF8); } catch { }
            return e;
        }

        private static IEnumerable<string> Candidates()
        {
            string exeDir = Path.GetDirectoryName(Environment.ProcessPath) ?? AppContext.BaseDirectory;
            yield return Path.Combine(exeDir, "ClamAV");
            yield return Path.Combine(exeDir, "ClamAV_Engine");
            string saved = null;
            try { if (File.Exists(SettingsFile)) saved = File.ReadAllText(SettingsFile, Encoding.UTF8).Trim(); } catch { }
            if (!string.IsNullOrEmpty(saved)) yield return saved;
            yield return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "ClamAV");
        }

        private static ClamAvEngine TryFolder(string dir)
        {
            if (string.IsNullOrWhiteSpace(dir)) return null;
            try
            {
                if (!File.Exists(Path.Combine(dir, "clamscan.exe")) || !File.Exists(Path.Combine(dir, "freshclam.exe"))) return null;
                return new ClamAvEngine { Folder = dir, DatabaseDir = PickDatabaseDir(dir) };
            }
            catch { return null; }
        }

        private static string PickDatabaseDir(string engineDir)
        {
            // 既に定義ファイルがある場所を優先（ClamAV の公式インストールは database\ に置く）
            string beside = Path.Combine(engineDir, "database");
            if (Directory.Exists(beside) && Directory.EnumerateFiles(beside, "*.c?d").Any()) return beside;
            if (Directory.EnumerateFiles(engineDir, "*.cvd").Any() || Directory.EnumerateFiles(engineDir, "*.cld").Any()) return engineDir;
            if (CanWrite(engineDir)) return beside;
            return Path.Combine(AppLog.DataDir, "clamav-db");
        }

        private static bool CanWrite(string dir)
        {
            try
            {
                string probe = Path.Combine(dir, ".aegis-write-test");
                File.WriteAllText(probe, "x");
                File.Delete(probe);
                return true;
            }
            catch { return false; }
        }

        /// <summary>「ClamAV 1.5.4/27800/…」のような版と定義の情報。</summary>
        public static async Task<string> GetVersionAsync(ClamAvEngine e)
        {
            var lines = new List<string>();
            var args = new List<string> { "--version" };
            if (e.HasDatabase) args.Add("--database=" + e.DatabaseDir);
            await RunAsync(e.ClamScan, args, lines.Add, CancellationToken.None);
            return lines.FirstOrDefault(l => l.StartsWith("ClamAV", StringComparison.OrdinalIgnoreCase)) ?? string.Join(" ", lines);
        }

        /// <summary>freshclam で定義ファイルを取得・更新する（インターネット接続が必要）。</summary>
        public static async Task<int> UpdateAsync(ClamAvEngine e, Action<string> log, CancellationToken ct)
        {
            Directory.CreateDirectory(e.DatabaseDir);
            // freshclam は証明書フォルダーが無いと止まる版がある（旧 VirusScannerApp と同じ対策）
            try { Directory.CreateDirectory(Path.Combine(e.Folder, "certs")); } catch { }

            string conf = Path.Combine(e.DatabaseDir, "freshclam.conf");
            File.WriteAllText(conf,
                "DatabaseDirectory " + e.DatabaseDir + "\n" +
                "UpdateLogFile " + Path.Combine(e.DatabaseDir, "freshclam.log") + "\n" +
                "DatabaseMirror database.clamav.net\n" +
                "ReceiveTimeout 120\n" +
                "ConnectTimeout 60\n" +
                "Bytecode true\n",
                new UTF8Encoding(false));

            return await RunAsync(e.FreshClam, new[] { "--config-file=" + conf, "--datadir=" + e.DatabaseDir, "--stdout" }, log, ct);
        }

        /// <summary>フォルダー（またはファイル）を clamscan で調べる。onFile はファイル 1 件ごとに呼ぶ。</summary>
        public static async Task<ClamAvScanResult> ScanAsync(ClamAvEngine e, string target, Action<string> log,
                                                             Action<int> onFile, Action<ClamAvHit> onHit, CancellationToken ct)
        {
            if (!e.HasDatabase) throw new InvalidOperationException("ClamAV の定義ファイルがありません。先に「定義ファイルを更新」を押してください。");

            var result = new ClamAvScanResult();
            bool summary = false;
            var args = new List<string> { "-r", "--database=" + e.DatabaseDir, "--stdout", target };

            Action<string> onLine = line =>
            {
                if (line.Contains("----------- SCAN SUMMARY -----------")) summary = true;
                if (summary) { result.Summary.Add(line); return; }

                if (line.EndsWith(" FOUND", StringComparison.Ordinal))
                {
                    // 「パス: シグネチャ名 FOUND」。パスにも「: 」が入り得るので最後の区切りで分ける
                    string body = line.Substring(0, line.Length - " FOUND".Length);
                    int sep = body.LastIndexOf(": ", StringComparison.Ordinal);
                    var hit = new ClamAvHit
                    {
                        FilePath = sep > 0 ? body.Substring(0, sep) : body,
                        Signature = sep > 0 ? body.Substring(sep + 2) : "(不明)"
                    };
                    result.Hits.Add(hit);
                    onHit?.Invoke(hit);
                    log?.Invoke(line);
                }
                else if (line.EndsWith(": OK", StringComparison.Ordinal) || line.EndsWith(": Empty file", StringComparison.Ordinal))
                {
                    // 正常なファイルは数えるだけ（ログには出さない）
                }
                else
                {
                    log?.Invoke(line);   // 読めない・警告など
                    // 「LibClamAV Warning: …」のような行はファイルとして数えない
                    if (!line.StartsWith(target, StringComparison.OrdinalIgnoreCase)) return;
                }
                result.FilesScanned++;
                onFile?.Invoke(result.FilesScanned);
            };

            try
            {
                result.ExitCode = await RunAsync(e.ClamScan, args, onLine, ct);
            }
            catch (OperationCanceledException)
            {
                result.Canceled = true;
            }
            return result;
        }

        /// <summary>プロセスを起動し、標準出力と標準エラーを 1 行ずつ渡す。中止したら木ごと止める。</summary>
        private static async Task<int> RunAsync(string exe, IEnumerable<string> args, Action<string> onLine, CancellationToken ct)
        {
            var psi = new ProcessStartInfo
            {
                FileName = exe,
                WorkingDirectory = Path.GetDirectoryName(exe),
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8,
            };
            foreach (string a in args) psi.ArgumentList.Add(a);

            using (var p = new Process { StartInfo = psi })
            {
                p.Start();
                var gate = new object();
                Action<string> emit = s => { if (string.IsNullOrWhiteSpace(s)) return; lock (gate) onLine?.Invoke(s.TrimEnd()); };
                var outTask = Task.Run(async () => { string s; while ((s = await p.StandardOutput.ReadLineAsync()) != null) emit(s); });
                var errTask = Task.Run(async () => { string s; while ((s = await p.StandardError.ReadLineAsync()) != null) emit(s); });

                using (ct.Register(() => { try { if (!p.HasExited) p.Kill(true); } catch { } }))
                {
                    await Task.WhenAll(outTask, errTask);
                    await p.WaitForExitAsync(CancellationToken.None);
                }
                ct.ThrowIfCancellationRequested();
                return p.ExitCode;
            }
        }
    }
}
