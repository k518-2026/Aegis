using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using Aegis.Models;

namespace Aegis.Services
{
    public class SignatureEntry
    {
        public string Sha256 { get; set; } = "";
        public string Name { get; set; } = "";
        public string Level { get; set; } = "High";
        public string Note { get; set; } = "";
    }

    /// <summary>
    /// ハッシュ定義データベース。
    /// 同梱の Resources\signatures.json と、ユーザー追加分
    /// （%LOCALAPPDATA%\Aegis\user-signatures.txt）を読み込みます。
    /// </summary>
    public class SignatureDatabase
    {
        private readonly Dictionary<string, SignatureEntry> _map =
            new Dictionary<string, SignatureEntry>(StringComparer.OrdinalIgnoreCase);

        public string Version { get; private set; } = "-";
        public string Updated { get; private set; } = "-";
        public int Count { get { return _map.Count; } }

        public static string UserSignaturePath
        {
            get { return Path.Combine(AppLog.DataDir, "user-signatures.txt"); }
        }

        public void Load()
        {
            _map.Clear();
            LoadBundled();
            LoadUserList();
        }

        private void LoadBundled()
        {
            try
            {
                string path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Resources", "signatures.json");
                if (!File.Exists(path)) return;

                using (JsonDocument doc = JsonDocument.Parse(File.ReadAllText(path)))
                {
                    JsonElement root = doc.RootElement;
                    JsonElement tmp;
                    if (root.TryGetProperty("version", out tmp)) Version = tmp.GetString();
                    if (root.TryGetProperty("updated", out tmp)) Updated = tmp.GetString();

                    if (root.TryGetProperty("entries", out tmp) && tmp.ValueKind == JsonValueKind.Array)
                    {
                        foreach (JsonElement e in tmp.EnumerateArray())
                        {
                            var entry = new SignatureEntry();
                            JsonElement v;
                            if (e.TryGetProperty("sha256", out v)) entry.Sha256 = (v.GetString() ?? "").Trim();
                            if (e.TryGetProperty("name", out v)) entry.Name = v.GetString() ?? "";
                            if (e.TryGetProperty("level", out v)) entry.Level = v.GetString() ?? "High";
                            if (e.TryGetProperty("note", out v)) entry.Note = v.GetString() ?? "";
                            if (entry.Sha256.Length == 64) _map[entry.Sha256] = entry;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                AppLog.Error("定義ファイルの読み込みに失敗: " + ex.Message);
            }
        }

        private void LoadUserList()
        {
            try
            {
                string path = UserSignaturePath;
                if (!File.Exists(path)) return;

                foreach (string raw in File.ReadAllLines(path))
                {
                    string line = raw.Trim();
                    if (line.Length == 0 || line.StartsWith("#")) continue;

                    // 形式: <sha256>[,名前[,レベル]]
                    string[] parts = line.Split(',');
                    string hash = parts[0].Trim();
                    if (hash.Length != 64) continue;

                    var entry = new SignatureEntry
                    {
                        Sha256 = hash,
                        Name = parts.Length > 1 ? parts[1].Trim() : "ユーザー定義",
                        Level = parts.Length > 2 ? parts[2].Trim() : "High",
                        Note = "ユーザー追加のハッシュ定義"
                    };
                    _map[hash] = entry;
                }
            }
            catch (Exception ex)
            {
                AppLog.Error("ユーザー定義の読み込みに失敗: " + ex.Message);
            }
        }

        /// <summary>ハッシュ一致を調べる</summary>
        public bool TryMatch(string sha256, out SignatureEntry entry)
        {
            entry = null;
            if (string.IsNullOrEmpty(sha256)) return false;
            return _map.TryGetValue(sha256, out entry);
        }

        public static ThreatLevel ParseLevel(string s)
        {
            ThreatLevel l;
            if (Enum.TryParse<ThreatLevel>(s, true, out l)) return l;
            return ThreatLevel.High;
        }

        /// <summary>ユーザー定義ファイルにハッシュを追記</summary>
        public static void AppendUserSignature(string sha256, string name, ThreatLevel level)
        {
            string path = UserSignaturePath;
            if (!File.Exists(path))
            {
                File.WriteAllText(path,
                    "# Aegis ユーザー定義ハッシュ" + Environment.NewLine +
                    "# 形式: <sha256>,<名前>,<Low|Medium|High|Critical>" + Environment.NewLine);
            }
            File.AppendAllText(path,
                string.Format("{0},{1},{2}{3}", sha256, name, level, Environment.NewLine));
        }
    }
}
