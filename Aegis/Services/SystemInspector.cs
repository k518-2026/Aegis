using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.Threading.Tasks;
using Aegis.Models;
using Microsoft.Win32;

namespace Aegis.Services
{
    /// <summary>Windows の保護設定を点検します（読み取りのみ）。</summary>
    public class SystemInspector
    {
        public Task<List<SystemCheckItem>> InspectAsync()
        {
            return Task.Run(() => Inspect());
        }

        public List<SystemCheckItem> Inspect()
        {
            var list = new List<SystemCheckItem>();
            SafeAdd(list, CheckDefender);
            SafeAdd(list, CheckSecurityCenterProducts);
            SafeAdd(list, CheckFirewall);
            SafeAdd(list, CheckSmartScreen);
            SafeAdd(list, CheckUac);
            SafeAdd(list, CheckWindowsUpdate);
            SafeAdd(list, CheckHostsFile);
            SafeAdd(list, CheckRemoteDesktop);
            SafeAdd(list, CheckSmb1);
            SafeAdd(list, CheckPowerShellPolicy);
            SafeAdd(list, CheckAutoRun);
            SafeAdd(list, CheckExtensionHiding);
            SafeAdd(list, CheckOsVersion);
            return list;
        }

        private static void SafeAdd(List<SystemCheckItem> list, Func<IEnumerable<SystemCheckItem>> f)
        {
            try { list.AddRange(f()); }
            catch (Exception ex) { AppLog.Warn("診断項目でエラー: " + ex.Message); }
        }

        // ---------------------------------------------------------------
        private IEnumerable<SystemCheckItem> CheckDefender()
        {
            var items = new List<SystemCheckItem>();
            try
            {
                var scope = new ManagementScope(@"\\.\root\Microsoft\Windows\Defender");
                scope.Connect();
                using (var searcher = new ManagementObjectSearcher(scope,
                    new ObjectQuery("SELECT * FROM MSFT_MpComputerStatus")))
                {
                    foreach (ManagementObject mo in searcher.Get())
                    {
                        bool rtp = ToBool(mo["RealTimeProtectionEnabled"]);
                        bool amEnabled = ToBool(mo["AntivirusEnabled"]);
                        object ageObj = mo["AntivirusSignatureAge"];
                        long age = ageObj == null ? -1 : Convert.ToInt64(ageObj);

                        items.Add(new SystemCheckItem
                        {
                            Category = "ウイルス対策",
                            Name = "Microsoft Defender リアルタイム保護",
                            Status = rtp ? CheckStatus.Ok : CheckStatus.Danger,
                            Detail = rtp ? "有効です。" : "無効になっています。",
                            Advice = rtp ? "" : "「Windows セキュリティ」→「ウイルスと脅威の防止」から有効にしてください。別のウイルス対策ソフトを使っている場合はそちらの状態を確認してください。"
                        });

                        items.Add(new SystemCheckItem
                        {
                            Category = "ウイルス対策",
                            Name = "定義ファイルの鮮度",
                            Status = age < 0 ? CheckStatus.Unknown : age <= 3 ? CheckStatus.Ok : age <= 7 ? CheckStatus.Warn : CheckStatus.Danger,
                            Detail = age < 0 ? "取得できませんでした。" : age + " 日前の定義です。",
                            Advice = age > 3 ? "Windows Update を実行して定義を更新してください。" : ""
                        });

                        if (!amEnabled)
                        {
                            items.Add(new SystemCheckItem
                            {
                                Category = "ウイルス対策",
                                Name = "Defender ウイルス対策エンジン",
                                Status = CheckStatus.Warn,
                                Detail = "無効です（他社製ソフト導入時は正常な状態です）。",
                                Advice = "他社製のウイルス対策ソフトを使っていない場合は有効にしてください。"
                            });
                        }
                        break;
                    }
                }
            }
            catch (Exception ex)
            {
                items.Add(new SystemCheckItem
                {
                    Category = "ウイルス対策",
                    Name = "Microsoft Defender",
                    Status = CheckStatus.Unknown,
                    Detail = "状態を取得できませんでした（" + ex.GetType().Name + "）。",
                    Advice = "管理者として実行すると取得できる場合があります。"
                });
            }
            return items;
        }

        private IEnumerable<SystemCheckItem> CheckSecurityCenterProducts()
        {
            var items = new List<SystemCheckItem>();
            try
            {
                var scope = new ManagementScope(@"\\.\root\SecurityCenter2");
                scope.Connect();
                var names = new List<string>();
                using (var s = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM AntiVirusProduct")))
                {
                    foreach (ManagementObject mo in s.Get())
                    {
                        string dn = Convert.ToString(mo["displayName"]);
                        int state = 0;
                        try { state = Convert.ToInt32(mo["productState"]); } catch { }
                        bool enabled = ((state >> 12) & 0x0F) != 0;
                        bool upToDate = ((state >> 8) & 0x0F) == 0;
                        names.Add(dn + "（" + (enabled ? "有効" : "無効") + " / " + (upToDate ? "最新" : "要更新") + "）");
                    }
                }
                items.Add(new SystemCheckItem
                {
                    Category = "ウイルス対策",
                    Name = "登録されているウイルス対策製品",
                    Status = names.Count > 0 ? CheckStatus.Ok : CheckStatus.Warn,
                    Detail = names.Count > 0 ? string.Join(" / ", names) : "登録された製品が見つかりません。",
                    Advice = names.Count > 0 ? "" : "ウイルス対策ソフトを1つは有効にしてください。"
                });
            }
            catch { }
            return items;
        }

        private IEnumerable<SystemCheckItem> CheckFirewall()
        {
            var items = new List<SystemCheckItem>();
            string[] profiles = { "DomainProfile", "StandardProfile", "PublicProfile" };
            string[] labels = { "ドメイン", "プライベート", "パブリック" };

            for (int i = 0; i < profiles.Length; i++)
            {
                object val = ReadHklm(
                    @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\" + profiles[i],
                    "EnableFirewall");
                bool on = val != null && Convert.ToInt32(val) == 1;
                items.Add(new SystemCheckItem
                {
                    Category = "ファイアウォール",
                    Name = "Windows ファイアウォール（" + labels[i] + "）",
                    Status = val == null ? CheckStatus.Unknown : on ? CheckStatus.Ok : CheckStatus.Danger,
                    Detail = val == null ? "設定値を取得できませんでした。" : on ? "有効です。" : "無効になっています。",
                    Advice = on ? "" : "「Windows セキュリティ」→「ファイアウォールとネットワーク保護」で有効にしてください。"
                });
            }
            return items;
        }

        private IEnumerable<SystemCheckItem> CheckSmartScreen()
        {
            object policy = ReadHklm(@"SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen");
            object explorerVal = ReadHklm(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", "SmartScreenEnabled");

            string detail;
            CheckStatus st;
            if (policy != null && Convert.ToInt32(policy) == 0)
            {
                st = CheckStatus.Danger; detail = "グループポリシーで無効化されています。";
            }
            else if (explorerVal != null)
            {
                string s = Convert.ToString(explorerVal);
                st = s.Equals("Off", StringComparison.OrdinalIgnoreCase) ? CheckStatus.Danger : CheckStatus.Ok;
                detail = "設定値: " + s;
            }
            else
            {
                st = CheckStatus.Ok; detail = "既定（有効）とみられます。";
            }

            yield return new SystemCheckItem
            {
                Category = "フィッシング対策",
                Name = "SmartScreen（危険なサイト・ファイルの警告）",
                Status = st,
                Detail = detail,
                Advice = st == CheckStatus.Ok ? "" : "「Windows セキュリティ」→「アプリとブラウザーの制御」→「評価ベースの保護」を有効にしてください。"
            };
        }

        private IEnumerable<SystemCheckItem> CheckUac()
        {
            object lua = ReadHklm(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA");
            object prompt = ReadHklm(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin");
            bool on = lua != null && Convert.ToInt32(lua) == 1;
            int level = prompt == null ? -1 : Convert.ToInt32(prompt);

            yield return new SystemCheckItem
            {
                Category = "システム保護",
                Name = "ユーザーアカウント制御（UAC）",
                Status = !on ? CheckStatus.Danger : level == 0 ? CheckStatus.Warn : CheckStatus.Ok,
                Detail = !on ? "無効です。" : level == 0 ? "有効ですが、確認なしで昇格する設定です。" : "有効です（確認画面あり）。",
                Advice = on && level != 0 ? "" : "コントロールパネルの「ユーザーアカウント制御の設定」を既定以上に戻してください。"
            };
        }

        private IEnumerable<SystemCheckItem> CheckWindowsUpdate()
        {
            object last = ReadHklm(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install",
                "LastSuccessTime");
            DateTime dt;
            if (last != null && DateTime.TryParse(Convert.ToString(last), out dt))
            {
                int days = (int)(DateTime.Now - dt).TotalDays;
                yield return new SystemCheckItem
                {
                    Category = "システム保護",
                    Name = "Windows Update の最終適用",
                    Status = days <= 35 ? CheckStatus.Ok : days <= 70 ? CheckStatus.Warn : CheckStatus.Danger,
                    Detail = dt.ToString("yyyy/MM/dd") + "（" + days + "日前）",
                    Advice = days > 35 ? "更新プログラムを適用してください。脆弱性の放置は感染の主要因です。" : ""
                };
            }
            else
            {
                yield return new SystemCheckItem
                {
                    Category = "システム保護",
                    Name = "Windows Update の最終適用",
                    Status = CheckStatus.Unknown,
                    Detail = "記録を取得できませんでした。",
                    Advice = "設定アプリから更新状況を確認してください。"
                };
            }
        }

        private IEnumerable<SystemCheckItem> CheckHostsFile()
        {
            string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),
                "drivers", "etc", "hosts");
            var suspicious = new List<string>();
            int entries = 0;
            string readError = null;
            try
            {
                if (File.Exists(path))
                {
                    foreach (string raw in File.ReadAllLines(path))
                    {
                        string line = raw.Trim();
                        if (line.Length == 0 || line.StartsWith("#")) continue;
                        entries++;
                        string lower = line.ToLowerInvariant();
                        if (lower.StartsWith("127.0.0.1") || lower.StartsWith("::1") || lower.StartsWith("0.0.0.0"))
                        {
                            // 広告ブロック等でよくある記述。セキュリティ製品のドメインを潰していないか確認
                            if (lower.Contains("windowsupdate") || lower.Contains("microsoft.com") ||
                                lower.Contains("defender") || lower.Contains("avast") || lower.Contains("norton") ||
                                lower.Contains("trendmicro") || lower.Contains("kaspersky") || lower.Contains("mcafee"))
                                suspicious.Add(line);
                        }
                        else
                        {
                            suspicious.Add(line);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                readError = ex.Message;
            }

            if (readError != null)
            {
                yield return new SystemCheckItem
                {
                    Category = "ネットワーク",
                    Name = "hosts ファイル",
                    Status = CheckStatus.Unknown,
                    Detail = "読み取れませんでした: " + readError
                };
                yield break;
            }

            yield return new SystemCheckItem
            {
                Category = "ネットワーク",
                Name = "hosts ファイルの改ざん",
                Status = suspicious.Count == 0 ? CheckStatus.Ok : CheckStatus.Warn,
                Detail = suspicious.Count == 0
                    ? "不審な書き換えは見つかりませんでした（有効行 " + entries + " 件）。"
                    : "次の行を確認してください:\n" + string.Join("\n", suspicious.Take(8)),
                Advice = suspicious.Count == 0 ? ""
                    : "身に覚えのない行はマルウェアによる通信先の付け替えや更新妨害の可能性があります。管理者権限でメモ帳を開き削除してください。"
            };
        }

        private IEnumerable<SystemCheckItem> CheckRemoteDesktop()
        {
            object deny = ReadHklm(@"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections");
            bool enabled = deny != null && Convert.ToInt32(deny) == 0;
            yield return new SystemCheckItem
            {
                Category = "ネットワーク",
                Name = "リモートデスクトップ",
                Status = enabled ? CheckStatus.Warn : CheckStatus.Ok,
                Detail = enabled ? "受け入れが有効です。" : "無効です。",
                Advice = enabled ? "使っていない場合は無効にしてください。インターネットに直接公開すると総当たり攻撃の標的になります。" : ""
            };
        }

        private IEnumerable<SystemCheckItem> CheckSmb1()
        {
            object v = ReadHklm(@"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1");
            bool enabled = v != null && Convert.ToInt32(v) == 1;
            yield return new SystemCheckItem
            {
                Category = "ネットワーク",
                Name = "SMBv1（古いファイル共有）",
                Status = enabled ? CheckStatus.Danger : CheckStatus.Ok,
                Detail = enabled ? "有効になっています。" : "無効、または既定で使用されていません。",
                Advice = enabled ? "ランサムウェアの拡散に悪用された古いプロトコルです。「Windowsの機能」から無効化してください。" : ""
            };
        }

        private IEnumerable<SystemCheckItem> CheckPowerShellPolicy()
        {
            object v = ReadHklm(@"SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell", "ExecutionPolicy");
            string s = v == null ? "未設定（既定: Restricted 相当）" : Convert.ToString(v);
            bool risky = s.IndexOf("Unrestricted", StringComparison.OrdinalIgnoreCase) >= 0 ||
                         s.IndexOf("Bypass", StringComparison.OrdinalIgnoreCase) >= 0;
            yield return new SystemCheckItem
            {
                Category = "システム保護",
                Name = "PowerShell 実行ポリシー",
                Status = risky ? CheckStatus.Warn : CheckStatus.Ok,
                Detail = "設定値: " + s,
                Advice = risky ? "Unrestricted / Bypass は任意のスクリプトが動く状態です。RemoteSigned 以上に戻すことを推奨します。" : ""
            };
        }

        private IEnumerable<SystemCheckItem> CheckAutoRun()
        {
            object v = ReadHklm(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun");
            int mask = v == null ? -1 : Convert.ToInt32(v);
            bool blocked = mask == 0xFF || mask == 0xB5;
            yield return new SystemCheckItem
            {
                Category = "システム保護",
                Name = "自動再生（USBメモリ）",
                Status = blocked ? CheckStatus.Ok : CheckStatus.Warn,
                Detail = v == null ? "既定設定です。" : "NoDriveTypeAutoRun = 0x" + mask.ToString("X2"),
                Advice = blocked ? "" : "USB経由の感染を防ぐため、設定アプリの「自動再生」をオフにすることを推奨します。"
            };
        }

        private IEnumerable<SystemCheckItem> CheckExtensionHiding()
        {
            object v = ReadHkcu(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "HideFileExt");
            bool hidden = v == null || Convert.ToInt32(v) == 1;
            yield return new SystemCheckItem
            {
                Category = "フィッシング対策",
                Name = "拡張子の表示",
                Status = hidden ? CheckStatus.Warn : CheckStatus.Ok,
                Detail = hidden ? "拡張子が隠されています。" : "拡張子が表示されています。",
                Advice = hidden ? "エクスプローラーの「表示」→「ファイル名拡張子」にチェックを入れてください。請求書.pdf.exe のような偽装を見破れます。" : ""
            };
        }

        private IEnumerable<SystemCheckItem> CheckOsVersion()
        {
            var os = Environment.OSVersion.Version;
            yield return new SystemCheckItem
            {
                Category = "システム保護",
                Name = "OS バージョン",
                Status = os.Major >= 10 ? CheckStatus.Ok : CheckStatus.Danger,
                Detail = "Windows " + (os.Build >= 22000 ? "11" : os.Major >= 10 ? "10" : os.Major.ToString()) +
                         "（ビルド " + os.Build + " / " + (Environment.Is64BitOperatingSystem ? "64bit" : "32bit") + "）",
                Advice = os.Major >= 10 ? "" : "サポートが終了したOSは更新が提供されません。移行を検討してください。"
            };
        }

        // ---------------------------------------------------------------
        private static object ReadHklm(string subKey, string valueName)
        {
            try
            {
                using (var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
                using (var k = baseKey.OpenSubKey(subKey))
                {
                    return k == null ? null : k.GetValue(valueName);
                }
            }
            catch { return null; }
        }

        private static object ReadHkcu(string subKey, string valueName)
        {
            try
            {
                using (var k = Registry.CurrentUser.OpenSubKey(subKey))
                {
                    return k == null ? null : k.GetValue(valueName);
                }
            }
            catch { return null; }
        }

        private static bool ToBool(object o)
        {
            try { return o != null && Convert.ToBoolean(o); } catch { return false; }
        }
    }
}
