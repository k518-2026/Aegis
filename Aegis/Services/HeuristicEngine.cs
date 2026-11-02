using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text.RegularExpressions;
using Aegis.Models;

namespace Aegis.Services
{
    /// <summary>
    /// ふるまい・形状ベースの検査エンジン。
    /// ハッシュ定義に載っていない未知のファイルでも、疑わしい特徴があれば警告します。
    /// </summary>
    public class HeuristicEngine
    {
        // 実行される可能性のある拡張子
        public static readonly HashSet<string> ExecutableExts = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".com", ".scr", ".pif", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
            ".wsf", ".wsh", ".ps1", ".psm1", ".msi", ".msp", ".hta", ".cpl", ".jar",
            ".lnk", ".reg", ".dll", ".sys", ".gadget", ".application", ".inf", ".iso", ".img"
        };

        // とくに正規の用途が少ない拡張子
        private static readonly HashSet<string> RareRiskyExts = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".scr", ".pif", ".hta", ".vbe", ".jse", ".wsf", ".wsh", ".cpl", ".com"
        };

        private static readonly HashSet<string> DocumentExts = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".csv",
            ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".mp3", ".mp4", ".avi", ".zip", ".rar", ".7z"
        };

        private static readonly HashSet<string> ScriptExts = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".bat", ".cmd", ".hta", ".wsf", ".py"
        };

        private static readonly HashSet<string> MacroExts = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".xlam", ".doc", ".xls", ".ppt"
        };

        // スクリプト内の要注意パターン（検出用のルール定義）
        private static readonly (string Pattern, string Reason, int Weight)[] ScriptPatterns = new[]
        {
            (@"-enc(odedcommand)?\s+[A-Za-z0-9+/=]{40,}", "Base64で難読化されたコマンドを実行しようとしています", 3),
            (@"frombase64string", "Base64を復号して実行する典型的な難読化です", 2),
            (@"downloadstring|downloadfile|invoke-webrequest|start-bitstransfer|urldownloadtofile",
                "外部からファイルやコードを取得しようとしています", 2),
            (@"invoke-expression|\biex\b|\beval\s*\(", "取得した文字列をそのまま実行しようとしています", 2),
            (@"vssadmin\s+delete\s+shadows|wbadmin\s+delete|bcdedit.*recoveryenabled\s+no",
                "復元ポイントやバックアップを削除しようとしています（ランサムウェアの典型）", 4),
            (@"cipher\s+/w|format\s+[a-z]:\s*/", "ディスクの消去・初期化を行おうとしています", 3),
            (@"set-mppreference.*disablerealtimemonitoring|add-mppreference.*exclusionpath",
                "ウイルス対策の保護を無効化・除外設定しようとしています", 4),
            (@"reg\s+add.*\\run\b|new-itemproperty.*currentversion\\run", "自動起動に自分を登録しようとしています", 2),
            (@"schtasks\s+/create", "タスクスケジューラに常駐しようとしています", 2),
            (@"net\s+user\s+\w+\s+\S+\s+/add|net\s+localgroup\s+administrators.*\/add",
                "管理者ユーザーを追加しようとしています", 3),
            (@"powershell.*-w(indowstyle)?\s+hidden|-nop\b|-noprofile.*-enc",
                "画面に出さずに実行する隠蔽オプションが使われています", 2),
            (@"mimikatz|sekurlsa|lsass.*dump", "資格情報の窃取に関係する語が含まれています", 4),
            (@"bitcoin|monero|wallet.*address.*ransom|your files have been encrypted",
                "身代金要求に関係する語が含まれています", 3),
        };

        public bool DeepInspection { get; set; } = true;

        /// <summary>1ファイルを検査して検出結果を返す</summary>
        public List<Detection> Inspect(FileInfo fi)
        {
            var results = new List<Detection>();
            if (fi == null) return results;

            string name = fi.Name;
            string path = fi.FullName;
            string ext = FileUtil.Ext(path);

            // --- R001 右から左へ上書き（RLO）文字によるファイル名偽装 ---
            if (name.IndexOf('\u202E') >= 0 || name.IndexOf('\u202B') >= 0 || name.IndexOf('\u200F') >= 0)
            {
                results.Add(Make(fi, "R001", "ファイル名の表示偽装（RLO）", ThreatLevel.Critical,
                    "拡張子を逆さまに見せる特殊な制御文字がファイル名に含まれています。" +
                    "画像や文書に見せかけた実行ファイルの典型的な手口です。"));
            }

            // --- R002 二重拡張子 ---
            var m = Regex.Match(name,
                @"\.(pdf|docx?|xlsx?|pptx?|txt|csv|jpe?g|png|gif|bmp|mp[34]|avi|zip|rar)\s*\.(exe|scr|com|pif|bat|cmd|vbs|vbe|js|jse|jar|lnk|hta|msi)$",
                RegexOptions.IgnoreCase);
            if (m.Success)
            {
                results.Add(Make(fi, "R002", "二重拡張子", ThreatLevel.High,
                    string.Format("「.{0}」に見せかけた「.{1}」形式の実行ファイルです。開かないでください。",
                        m.Groups[1].Value, m.Groups[2].Value)));
            }

            // --- R003 名前と中身の不一致（拡張子偽装） ---
            byte[] head = FileUtil.ReadHead(path, 4096);
            bool isPe = FileUtil.IsPortableExecutable(head);
            if (isPe && DocumentExts.Contains(ext))
            {
                results.Add(Make(fi, "R003", "拡張子の偽装", ThreatLevel.High,
                    string.Format("拡張子は「{0}」ですが、中身はWindowsの実行ファイル（PE形式）です。", ext)));
            }

            // --- R004 実行される可能性のある拡張子 ---
            if (RareRiskyExts.Contains(ext))
            {
                results.Add(Make(fi, "R004", "危険度の高い形式", ThreatLevel.Low,
                    string.Format("「{0}」は正規のソフトではあまり使われず、攻撃で好まれる形式です。心当たりがなければ削除してください。", ext)));
            }

            // --- R005 一時フォルダ／ダウンロードの実行ファイル ---
            if ((isPe || ExecutableExts.Contains(ext)) && IsTransientLocation(path))
            {
                results.Add(Make(fi, "R005", "一時領域の実行ファイル", ThreatLevel.Low,
                    "一時フォルダやダウンロードフォルダに実行ファイルがあります。マルウェアが最初に置かれやすい場所です。"));
            }

            // --- R006 スクリプトの内容検査 ---
            if (DeepInspection && ScriptExts.Contains(ext) && fi.Length <= 4L * 1024 * 1024)
            {
                string text = FileUtil.ReadTextHead(path, 512 * 1024);
                if (!string.IsNullOrEmpty(text))
                {
                    string lower = text.ToLowerInvariant();
                    var hits = new List<string>();
                    int weight = 0;
                    foreach (var p in ScriptPatterns)
                    {
                        try
                        {
                            if (Regex.IsMatch(lower, p.Pattern, RegexOptions.IgnoreCase))
                            {
                                hits.Add("・" + p.Reason);
                                weight += p.Weight;
                            }
                        }
                        catch { }
                    }

                    if (hits.Count > 0)
                    {
                        ThreatLevel lv = weight >= 6 ? ThreatLevel.Critical
                                       : weight >= 4 ? ThreatLevel.High
                                       : ThreatLevel.Medium;
                        results.Add(Make(fi, "R006", "スクリプトの不審な処理", lv,
                            "次の動作が見つかりました。\n" + string.Join("\n", hits.Distinct())));
                    }

                    // 極端に長い1行 = 難読化の疑い
                    int longest = text.Split('\n').Select(l => l.Length).DefaultIfEmpty(0).Max();
                    if (longest > 3000)
                    {
                        results.Add(Make(fi, "R007", "難読化の疑い", ThreatLevel.Medium,
                            string.Format("1行が{0}文字と極端に長く、内容を読みにくくする難読化が疑われます。", longest)));
                    }
                }
            }

            // --- R008 ショートカット（.lnk）からのコマンド実行 ---
            if (ext == ".lnk" && fi.Length < 512 * 1024)
            {
                string raw = System.Text.Encoding.ASCII.GetString(FileUtil.ReadHead(path, (int)Math.Min(fi.Length, 262144)));
                string cleaned = new string(raw.Where(c => c >= 32 && c < 127).ToArray()).ToLowerInvariant();
                if (Regex.IsMatch(cleaned, @"powershell|cmd\.exe\s*/c|mshta|wscript|cscript|rundll32|curl|certutil"))
                {
                    results.Add(Make(fi, "R008", "コマンドを実行するショートカット", ThreatLevel.High,
                        "ショートカットが PowerShell やコマンドプロンプトを起動する内容になっています。" +
                        "メール添付やUSBから来たものであれば開かないでください。"));
                }
            }

            // --- R009 Officeマクロ ---
            if (DeepInspection && MacroExts.Contains(ext))
            {
                if (HasVbaMacro(path, head))
                {
                    results.Add(Make(fi, "R009", "マクロ入りの文書", ThreatLevel.Medium,
                        "VBAマクロが埋め込まれています。差出人に心当たりがない場合は「コンテンツの有効化」を押さないでください。"));
                }
            }

            // --- R010 エントロピー（パック・暗号化） ---
            if (DeepInspection && isPe && fi.Length > 4096)
            {
                double e = FileUtil.Entropy(FileUtil.ReadHead(path, 1024 * 1024));
                if (e >= 7.5)
                {
                    results.Add(Make(fi, "R010", "圧縮・難読化された実行ファイル", ThreatLevel.Low,
                        string.Format("データの乱雑さ（エントロピー {0:0.00}/8.00）が高く、解析されにくいよう圧縮・暗号化されている可能性があります。", e)));
                }
            }

            // --- R011 デジタル署名なしの実行ファイル ---
            if (DeepInspection && isPe && ext != ".sys")
            {
                string signer;
                if (!FileUtil.TryGetSigner(path, out signer))
                {
                    results.Add(Make(fi, "R011", "デジタル署名なし", ThreatLevel.Info,
                        "発行元のデジタル署名がありません。個人開発のソフトでも普通にあることですが、" +
                        "有名企業のソフトを名乗っている場合は偽物の可能性があります。"));
                }
            }

            // --- R012 インターネット由来のマーク ---
            if (isPe || ExecutableExts.Contains(ext))
            {
                if (FileUtil.HasMarkOfTheWeb(path))
                {
                    results.Add(Make(fi, "R012", "インターネットから取得", ThreatLevel.Info,
                        "この実行ファイルはインターネットからダウンロードされたものです。入手元を確認してください。"));
                }
            }

            // --- R013 隠し属性 + 実行ファイル ---
            try
            {
                if ((isPe || ExecutableExts.Contains(ext)) &&
                    (fi.Attributes & FileAttributes.Hidden) == FileAttributes.Hidden &&
                    !path.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.Windows), StringComparison.OrdinalIgnoreCase))
                {
                    results.Add(Make(fi, "R013", "隠し属性の実行ファイル", ThreatLevel.Medium,
                        "実行ファイルが隠しファイルとして置かれています。意図的に見つかりにくくしている可能性があります。"));
                }
            }
            catch { }

            // --- R014 名前による偽装（正規プロセス名の詐称） ---
            string bare = Path.GetFileNameWithoutExtension(name).ToLowerInvariant();
            string[] systemNames = { "svchost", "csrss", "lsass", "winlogon", "services", "explorer", "smss", "conhost", "dwm" };
            if (isPe && systemNames.Contains(bare) && !IsInWindowsDir(path))
            {
                results.Add(Make(fi, "R014", "システムプロセス名の詐称", ThreatLevel.Critical,
                    string.Format("Windows標準プロセスと同じ名前「{0}」ですが、システムフォルダ以外に置かれています。", name)));
            }

            // --- R015 空白の多いファイル名 ---
            if (Regex.IsMatch(name, @"\s{6,}\.\w+$"))
            {
                results.Add(Make(fi, "R015", "拡張子を隠すファイル名", ThreatLevel.Medium,
                    "拡張子の前に大量の空白が入っており、本当の拡張子を画面外に隠す手口の可能性があります。"));
            }

            return results;
        }

        private static bool IsInWindowsDir(string path)
        {
            try
            {
                string win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
                return path.StartsWith(win, StringComparison.OrdinalIgnoreCase);
            }
            catch { return false; }
        }

        private static bool IsTransientLocation(string path)
        {
            try
            {
                string[] dirs =
                {
                    Path.GetTempPath(),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                    Environment.GetFolderPath(Environment.SpecialFolder.InternetCache)
                };
                foreach (string d in dirs)
                {
                    if (!string.IsNullOrEmpty(d) && path.StartsWith(d, StringComparison.OrdinalIgnoreCase))
                        return true;
                }
            }
            catch { }
            return false;
        }

        private static bool HasVbaMacro(string path, byte[] head)
        {
            try
            {
                if (FileUtil.IsZipContainer(head))
                {
                    using (var zip = ZipFile.OpenRead(path))
                    {
                        foreach (var e in zip.Entries)
                        {
                            if (e.FullName.EndsWith("vbaProject.bin", StringComparison.OrdinalIgnoreCase))
                                return true;
                        }
                    }
                    return false;
                }

                if (FileUtil.IsOleCompound(head))
                {
                    // 旧形式は OLE を解析せず、既知の文字列で簡易判定
                    byte[] body = FileUtil.ReadHead(path, 2 * 1024 * 1024);
                    string ascii = System.Text.Encoding.ASCII.GetString(body);
                    string utf16 = System.Text.Encoding.Unicode.GetString(body);
                    return ascii.IndexOf("VBA", StringComparison.OrdinalIgnoreCase) >= 0
                        || utf16.IndexOf("VBA", StringComparison.OrdinalIgnoreCase) >= 0;
                }
            }
            catch { }
            return false;
        }

        private static Detection Make(FileInfo fi, string id, string rule, ThreatLevel level, string desc)
        {
            return new Detection
            {
                FilePath = fi.FullName,
                FileName = fi.Name,
                Size = SafeLength(fi),
                RuleId = id,
                RuleName = rule,
                Level = level,
                Description = desc
            };
        }

        private static long SafeLength(FileInfo fi)
        {
            try { return fi.Length; } catch { return 0; }
        }
    }
}
