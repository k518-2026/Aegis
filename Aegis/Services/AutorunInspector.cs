using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Aegis.Models;
using Microsoft.Win32;

namespace Aegis.Services
{
    /// <summary>Windows起動時に自動実行される項目を洗い出します。</summary>
    public class AutorunInspector
    {
        public Task<List<AutorunItem>> InspectAsync()
        {
            return Task.Run(() => Inspect());
        }

        public List<AutorunItem> Inspect()
        {
            var list = new List<AutorunItem>();

            ReadRunKey(list, RegistryHive.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU\\Run");
            ReadRunKey(list, RegistryHive.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU\\RunOnce");
            ReadRunKey(list, RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Run");
            ReadRunKey(list, RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\RunOnce");
            ReadRunKey(list, RegistryHive.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Run (32bit)");

            ReadStartupFolder(list, Environment.GetFolderPath(Environment.SpecialFolder.Startup), "スタートアップ（個人）");
            ReadStartupFolder(list, Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), "スタートアップ（全員）");

            foreach (var item in list) Evaluate(item);
            return list;
        }

        private static void ReadRunKey(List<AutorunItem> list, RegistryHive hive, string sub, string label)
        {
            try
            {
                using (var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64))
                using (var k = baseKey.OpenSubKey(sub))
                {
                    if (k == null) return;
                    foreach (string name in k.GetValueNames())
                    {
                        string cmd = Convert.ToString(k.GetValue(name));
                        if (string.IsNullOrWhiteSpace(cmd)) continue;
                        list.Add(new AutorunItem
                        {
                            Source = label,
                            Name = name,
                            Command = cmd,
                            ResolvedPath = ExtractPath(cmd)
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                AppLog.Warn("自動起動キーの読み取りに失敗: " + label + " / " + ex.Message);
            }
        }

        private static void ReadStartupFolder(List<AutorunItem> list, string dir, string label)
        {
            try
            {
                if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) return;
                foreach (string f in Directory.EnumerateFiles(dir))
                {
                    string n = Path.GetFileName(f);
                    if (n.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;
                    list.Add(new AutorunItem
                    {
                        Source = label,
                        Name = n,
                        Command = f,
                        ResolvedPath = f
                    });
                }
            }
            catch (Exception ex)
            {
                AppLog.Warn("スタートアップの読み取りに失敗: " + ex.Message);
            }
        }

        private static string ExtractPath(string command)
        {
            if (string.IsNullOrWhiteSpace(command)) return "";
            command = command.Trim();

            if (command.StartsWith("\""))
            {
                int end = command.IndexOf('"', 1);
                if (end > 1) return command.Substring(1, end - 1);
            }

            var m = Regex.Match(command, @"^[^\s]+(\.exe|\.bat|\.cmd|\.com|\.scr|\.vbs|\.js|\.lnk)", RegexOptions.IgnoreCase);
            if (m.Success) return m.Value;

            int sp = command.IndexOf(' ');
            return sp > 0 ? command.Substring(0, sp) : command;
        }

        private static void Evaluate(AutorunItem item)
        {
            var notes = new List<string>();
            var level = ThreatLevel.Info;
            string cmdLower = (item.Command ?? "").ToLowerInvariant();

            string temp = Path.GetTempPath().ToLowerInvariant();
            string appdata = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData).ToLowerInvariant();
            string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData).ToLowerInvariant();

            if (cmdLower.Contains(temp))
            {
                notes.Add("一時フォルダから起動しています");
                level = ThreatLevel.High;
            }
            else if ((cmdLower.Contains(appdata) || cmdLower.Contains(local)) &&
                     !cmdLower.Contains("microsoft") && !cmdLower.Contains("programs"))
            {
                notes.Add("AppData 配下から起動しています");
                if (level < ThreatLevel.Medium) level = ThreatLevel.Medium;
            }

            if (Regex.IsMatch(cmdLower, @"powershell|mshta|wscript|cscript|rundll32|regsvr32|certutil|curl\s|bitsadmin"))
            {
                notes.Add("スクリプト実行系のコマンドを使っています");
                if (level < ThreatLevel.Medium) level = ThreatLevel.Medium;
            }

            if (Regex.IsMatch(cmdLower, @"-enc(odedcommand)?\s+[a-z0-9+/=]{30,}|frombase64string"))
            {
                notes.Add("難読化されたコマンドが含まれています");
                level = ThreatLevel.Critical;
            }

            if (Regex.IsMatch(cmdLower, @"-w(indowstyle)?\s+hidden|/min\b|-nop\b"))
            {
                notes.Add("画面に表示せず起動する設定です");
                if (level < ThreatLevel.Medium) level = ThreatLevel.Medium;
            }

            try
            {
                if (!string.IsNullOrEmpty(item.ResolvedPath) && File.Exists(item.ResolvedPath))
                {
                    string signer;
                    if (FileUtil.TryGetSigner(item.ResolvedPath, out signer))
                    {
                        item.Signer = signer;
                    }
                    else
                    {
                        item.Signer = "（署名なし）";
                        notes.Add("発行元の署名がありません");
                        if (level < ThreatLevel.Low) level = ThreatLevel.Low;
                    }
                }
                else if (!string.IsNullOrEmpty(item.ResolvedPath))
                {
                    item.Signer = "-";
                    notes.Add("実体のファイルが見つかりません（削除済みの残骸の可能性）");
                    if (level < ThreatLevel.Low) level = ThreatLevel.Low;
                }
            }
            catch { }

            item.Level = level;
            item.Note = notes.Count == 0 ? "特筆すべき点はありません" : string.Join(" / ", notes);
        }

        /// <summary>レジストリの自動起動エントリを削除する</summary>
        public static void RemoveRunEntry(AutorunItem item)
        {
            if (item.Source.StartsWith("スタートアップ"))
            {
                if (File.Exists(item.Command)) File.Delete(item.Command);
                return;
            }

            RegistryHive hive = item.Source.StartsWith("HKCU") ? RegistryHive.CurrentUser : RegistryHive.LocalMachine;
            string sub = item.Source.Contains("32bit")
                ? @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
                : item.Source.Contains("RunOnce")
                    ? @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
                    : @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";

            using (var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64))
            using (var k = baseKey.OpenSubKey(sub, true))
            {
                if (k != null) k.DeleteValue(item.Name, false);
            }
        }
    }
}
