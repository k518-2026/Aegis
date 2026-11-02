using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Aegis.Models;

namespace Aegis.Services
{
    /// <summary>
    /// 指定フォルダを監視し、新しく現れたファイルをその場で検査します。
    /// （常駐型ウイルス対策の代わりではなく、補助的な見張りです）
    /// </summary>
    public class RealtimeMonitor : IDisposable
    {
        private readonly List<FileSystemWatcher> _watchers = new List<FileSystemWatcher>();
        private readonly SignatureDatabase _db;
        private readonly HeuristicEngine _heur = new HeuristicEngine();
        private readonly Dictionary<string, DateTime> _recent = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        private readonly object _lock = new object();

        public bool IsRunning { get; private set; }

        /// <summary>検出時に発火（UIスレッドではないので Dispatcher 経由で使うこと）</summary>
        public event Action<Detection> Detected;
        public event Action<string> FileSeen;

        public RealtimeMonitor(SignatureDatabase db)
        {
            _db = db;
        }

        public static List<string> DefaultFolders()
        {
            var list = new List<string>();
            void Add(string p) { if (!string.IsNullOrEmpty(p) && Directory.Exists(p)) list.Add(p); }
            Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"));
            Add(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory));
            Add(Path.GetTempPath());
            return list;
        }

        public void Start(IEnumerable<string> folders)
        {
            Stop();
            foreach (string dir in folders)
            {
                if (!Directory.Exists(dir)) continue;
                try
                {
                    var w = new FileSystemWatcher(dir)
                    {
                        IncludeSubdirectories = true,
                        NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size,
                        InternalBufferSize = 65536
                    };
                    w.Created += OnChanged;
                    w.Renamed += OnRenamed;
                    w.Changed += OnChanged;
                    w.Error += (s, e) => AppLog.Warn("監視エラー: " + e.GetException().Message);
                    w.EnableRaisingEvents = true;
                    _watchers.Add(w);
                }
                catch (Exception ex)
                {
                    AppLog.Warn("監視の開始に失敗: " + dir + " / " + ex.Message);
                }
            }
            IsRunning = _watchers.Count > 0;
            AppLog.Info("リアルタイム監視を開始: " + _watchers.Count + " フォルダ");
        }

        public void Stop()
        {
            foreach (var w in _watchers)
            {
                try { w.EnableRaisingEvents = false; w.Dispose(); } catch { }
            }
            _watchers.Clear();
            IsRunning = false;
        }

        private void OnRenamed(object sender, RenamedEventArgs e) { Handle(e.FullPath); }
        private void OnChanged(object sender, FileSystemEventArgs e) { Handle(e.FullPath); }

        private void Handle(string path)
        {
            if (string.IsNullOrEmpty(path)) return;

            lock (_lock)
            {
                DateTime last;
                if (_recent.TryGetValue(path, out last) && (DateTime.Now - last).TotalSeconds < 5) return;
                _recent[path] = DateTime.Now;
                if (_recent.Count > 500) _recent.Clear();
            }

            Task.Run(() =>
            {
                try
                {
                    // 書き込み完了を待つ
                    for (int i = 0; i < 10; i++)
                    {
                        if (!IsLocked(path)) break;
                        Thread.Sleep(400);
                    }

                    var fi = new FileInfo(path);
                    if (!fi.Exists || fi.Length == 0) return;
                    if (fi.Length > 300L * 1024 * 1024) return;

                    var seen = FileSeen;
                    if (seen != null) seen(path);

                    var results = new List<Detection>();

                    string hash = FileUtil.Sha256(path);
                    SignatureEntry entry;
                    if (hash != null && _db.TryMatch(hash, out entry))
                    {
                        results.Add(new Detection
                        {
                            FilePath = path,
                            FileName = fi.Name,
                            Sha256 = hash,
                            Size = fi.Length,
                            RuleId = "SIG",
                            RuleName = "定義ファイル一致: " + entry.Name,
                            Level = SignatureDatabase.ParseLevel(entry.Level),
                            Description = entry.Note
                        });
                    }

                    foreach (var d in _heur.Inspect(fi))
                    {
                        if (d.Level <= ThreatLevel.Info) continue;
                        d.Sha256 = hash ?? "";
                        results.Add(d);
                    }

                    var handler = Detected;
                    if (handler != null)
                    {
                        foreach (var d in results) handler(d);
                    }
                }
                catch (Exception ex)
                {
                    AppLog.Warn("監視中の検査に失敗: " + path + " / " + ex.Message);
                }
            });
        }

        private static bool IsLocked(string path)
        {
            try
            {
                using (new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.None)) { return false; }
            }
            catch (IOException) { return true; }
            catch { return false; }
        }

        public void Dispose() { Stop(); }
    }
}
