using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;
using Aegis.Models;

namespace Aegis.Services
{
    /// <summary>
    /// URL とメール本文をルールベースで採点し、フィッシングの疑いを判定します。
    /// 外部サービスへの問い合わせは行わず、すべて端末内で完結します。
    /// </summary>
    public class PhishingAnalyzer
    {
        // よく偽装される正規ドメイン
        private static readonly string[] KnownBrands =
        {
            "amazon.co.jp", "amazon.com", "rakuten.co.jp", "rakuten-card.co.jp", "apple.com",
            "microsoft.com", "office.com", "live.com", "google.com", "youtube.com",
            "paypal.com", "paypay.ne.jp", "line.me", "netflix.com", "facebook.com", "instagram.com",
            "x.com", "twitter.com", "jcb.co.jp", "smbc-card.com", "smbc.co.jp", "mufg.jp",
            "bk.mufg.jp", "mizuhobank.co.jp", "japanpost.jp", "jp-bank.japanpost.jp",
            "aeon.co.jp", "aeonbank.co.jp", "etc-meisai.jp", "nta.go.jp", "e-tax.nta.go.jp",
            "kuronekoyamato.co.jp", "sagawa-exp.co.jp", "jreast.co.jp", "docomo.ne.jp",
            "au.com", "softbank.jp", "ymobile.jp", "mercari.com", "yahoo.co.jp", "epos-card.co.jp",
            "saisoncard.co.jp", "orico.co.jp", "nicos.co.jp", "vpass.ne.jp", "tepco.co.jp",
            "dropbox.com", "adobe.com", "steampowered.com", "binance.com", "coincheck.com"
        };

        // 危険なTLD（フィッシングでの利用率が高い、または誤認を狙うもの）
        private static readonly string[] RiskyTlds =
        {
            ".zip", ".mov", ".top", ".xyz", ".click", ".cyou", ".rest", ".cam", ".work",
            ".buzz", ".icu", ".gq", ".cf", ".tk", ".ml", ".ga", ".loan", ".shop", ".vip",
            ".live", ".fun", ".bar", ".surf", ".monster", ".quest", ".sbs", ".autos"
        };

        private static readonly string[] Shorteners =
        {
            "bit.ly", "t.co", "tinyurl.com", "is.gd", "ow.ly", "buff.ly", "goo.gl",
            "rb.gy", "cutt.ly", "t.ly", "shorturl.at", "lnkd.in", "urlz.fr", "x.gd"
        };

        private static readonly string[] LureWords =
        {
            "login", "signin", "logon", "verify", "verification", "secure", "security",
            "account", "update", "confirm", "webscr", "wallet", "billing", "payment",
            "unlock", "recovery", "support", "auth", "session", "invoice", "refund"
        };

        private static readonly string[] MultiLevelSuffixes =
        {
            "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "ed.jp", "gr.jp", "lg.jp",
            "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "com.cn", "net.cn", "org.cn",
            "com.br", "co.kr", "com.tw", "com.hk", "com.sg", "co.in", "com.mx"
        };

        // 日本語のフィッシング文面で頻出する表現
        private static readonly (string Pattern, string Reason, int Score)[] MailPhrases = new[]
        {
            (@"アカウント.{0,10}(停止|制限|ロック|凍結|無効)", "アカウント停止をちらつかせて焦らせています", 20),
            (@"(24|48|72)\s*時間以内|本日中に|至急|お急ぎください|期限が切れ", "時間的な切迫感をあおっています", 15),
            (@"本人確認|ご本人様確認|情報を更新|再登録|認証手続き", "個人情報の再入力を求めています", 15),
            (@"お支払い.{0,10}(確認|failed|失敗|できません)|未払い|滞納|請求", "未払いを口実にしています", 15),
            (@"荷物.{0,10}(お届け|配達).{0,10}(できません|不在)|再配達", "宅配の不在通知をかたっています", 15),
            (@"当選|高額報酬|還付金|返金され", "金銭的な誘いで気を引いています", 15),
            (@"クレジットカード番号|暗証番号|セキュリティコード|ワンタイムパスワード|マイナンバー",
                "本来メールで尋ねてはいけない情報を求めています", 25),
            (@"下記(の)?(リンク|URL).{0,20}(クリック|アクセス)", "リンクへの誘導が主目的の文面です", 10),
        };

        // ==================================================================
        // URL 判定
        // ==================================================================
        public UrlVerdict AnalyzeUrl(string input)
        {
            var v = new UrlVerdict { Url = (input ?? "").Trim() };
            if (v.Url.Length == 0) return v;

            string work = v.Url;
            if (!Regex.IsMatch(work, @"^[a-zA-Z][a-zA-Z0-9+.\-]*:"))
                work = "http://" + work;

            // 危険なスキーム
            var schemeMatch = Regex.Match(work, @"^([a-zA-Z][a-zA-Z0-9+.\-]*):");
            string scheme = schemeMatch.Success ? schemeMatch.Groups[1].Value.ToLowerInvariant() : "";
            if (scheme == "javascript" || scheme == "data" || scheme == "vbscript")
            {
                Add(v, "実行用スキーム", scheme + ": はページを開くのではなくコードを実行させる形式です。", 45);
                return v;
            }

            Uri uri;
            if (!Uri.TryCreate(work, UriKind.Absolute, out uri))
            {
                Add(v, "解析不能", "URLとして正しく解釈できませんでした。手打ちで確認してください。", 20);
                return v;
            }

            string host = (uri.Host ?? "").ToLowerInvariant();
            v.Host = host;
            string path = uri.AbsolutePath ?? "";
            string query = uri.Query ?? "";
            string all = (host + path + query).ToLowerInvariant();

            // 1) HTTPS でない
            if (scheme == "http")
                Add(v, "暗号化なし（HTTP）", "通信が暗号化されていません。ログイン情報を入力してはいけません。", 15);

            // 2) ホストがIPアドレス
            if (uri.HostNameType == UriHostNameType.IPv4 || uri.HostNameType == UriHostNameType.IPv6)
                Add(v, "IPアドレス直指定", "正規のサービスがIPアドレスのままリンクを配ることはまずありません。", 30);

            // 3) ユーザー情報（@）による偽装
            if (!string.IsNullOrEmpty(uri.UserInfo) || Regex.IsMatch(v.Url, @"https?://[^/\s]*@"))
                Add(v, "@ による表示偽装", "@ の前は無視されるため、本物のドメインに見せかける手口です。", 35);

            // 4) Punycode / 文字体系の混在
            if (host.Contains("xn--"))
            {
                string decoded = host;
                try { decoded = new IdnMapping().GetUnicode(host); } catch { }
                Add(v, "Punycode ドメイン", "見た目が似た別文字で作られたドメインの可能性があります（復号: " + decoded + "）。", 30);
            }
            if (HasMixedScript(host))
                Add(v, "文字体系の混在", "ラテン文字とキリル文字などが混在しており、偽装ドメインの典型です。", 35);

            // 5) 非標準ポート
            if (!uri.IsDefaultPort)
                Add(v, "非標準ポート", "ポート " + uri.Port + " が指定されています。通常のサイトでは珍しい構成です。", 12);

            // 6) サブドメインの深さ
            string[] labels = host.Split('.');
            if (labels.Length >= 5)
                Add(v, "サブドメインが多い", "階層が" + labels.Length + "段あり、正規ドメインらしく見せる細工が疑われます。", 12);

            // 7) 長さ・記号
            if (v.Url.Length > 90)
                Add(v, "URLが長い", v.Url.Length + "文字と長く、本来のあて先を見えにくくしています。", 8);
            int hyphens = host.Count(c => c == '-');
            if (hyphens >= 3)
                Add(v, "ハイフンが多い", "ドメイン名にハイフンが" + hyphens + "個含まれています。", 10);

            // 8) 危険なTLD
            foreach (string tld in RiskyTlds)
            {
                if (host.EndsWith(tld, StringComparison.OrdinalIgnoreCase))
                {
                    Add(v, "注意が必要なTLD", tld + " は詐欺サイトに使われる割合が高いドメインです。", 18);
                    break;
                }
            }

            // 9) 短縮URL
            string reg = GetRegistrableDomain(host);
            if (Shorteners.Contains(reg))
                Add(v, "短縮URL", "本当のあて先が隠れています。展開してから中身を確認してください。", 12);

            // 10) ブランドのなりすまし
            string brandHit = KnownBrands.FirstOrDefault(b =>
                host.Contains(b.Split('.')[0]) && b.Split('.')[0].Length >= 4);
            if (brandHit != null && !IsOfficial(host))
            {
                Add(v, "有名ブランドの名前を含む",
                    "「" + brandHit.Split('.')[0] + "」を名乗っていますが、公式ドメイン（" + brandHit + "）ではありません。", 40);
            }

            // 11) タイポスクワッティング
            string typo = FindTyposquat(reg);
            if (typo != null)
                Add(v, "そっくりドメイン", "正規の " + typo + " と1〜2文字しか違いません。読み間違いを狙っています。", 40);

            // 12) 誘導ワード
            var lures = LureWords.Where(w => all.Contains(w)).Take(4).ToList();
            if (lures.Count >= 2)
                Add(v, "ログイン誘導ワード", "URLに " + string.Join(" / ", lures) + " が含まれています。", 12);
            else if (lures.Count == 1 && host.Contains(lures[0]))
                Add(v, "ログイン誘導ワード", "ドメイン名に " + lures[0] + " が含まれています。", 10);

            // 13) 実行ファイルへの直リンク
            if (Regex.IsMatch(path, @"\.(exe|scr|msi|bat|cmd|jar|apk|vbs|ps1|hta|zip|rar|7z|iso)$", RegexOptions.IgnoreCase))
                Add(v, "ファイルの直接ダウンロード", "リンク先がファイルそのものです。自動的に保存される可能性があります。", 22);

            // 14) 正規ドメインを文字列として埋め込む手口
            if (Regex.IsMatch(host, @"(amazon|apple|rakuten|paypal|microsoft|google)[-.]?(co|com|jp|net)?[-.]", RegexOptions.IgnoreCase)
                && !IsOfficial(host))
                Add(v, "ドメイン名の水増し", "正規ドメインを部分文字列として含む長いホスト名です。", 20);

            // 15) 公式ドメインなら減点情報
            if (IsOfficial(host))
                Add(v, "公式ドメインと一致", "登録ドメイン " + reg + " は既知の正規ドメインと一致します。", 0);

            v.Score = Math.Min(100, v.Signals.Sum(s => s.Score));
            return v;
        }

        /// <summary>メール本文からURLを取り出して個別に判定する</summary>
        public List<UrlVerdict> AnalyzeText(string text)
        {
            var results = new List<UrlVerdict>();
            if (string.IsNullOrWhiteSpace(text)) return results;

            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (Match m in Regex.Matches(text, @"(?:https?://|www\.)[^\s<>""'）)\]]+", RegexOptions.IgnoreCase))
            {
                string u = m.Value.TrimEnd('.', ',', '。', '、', '>', ':', ';');
                if (seen.Add(u)) results.Add(AnalyzeUrl(u));
            }
            return results;
        }

        /// <summary>メール本文そのものの文面診断</summary>
        public UrlVerdict AnalyzeMailBody(string text)
        {
            var v = new UrlVerdict { Url = "（本文の文面診断）", Host = "-" };
            if (string.IsNullOrWhiteSpace(text)) return v;

            foreach (var p in MailPhrases)
            {
                try
                {
                    var m = Regex.Match(text, p.Pattern, RegexOptions.IgnoreCase);
                    if (m.Success)
                        Add(v, "文面の特徴", p.Reason + "（該当箇所: " + Trim(m.Value, 24) + "）", p.Score);
                }
                catch { }
            }

            // HTMLリンクの表示テキストとあて先の不一致
            foreach (Match m in Regex.Matches(text,
                @"<a[^>]+href\s*=\s*[""']([^""']+)[""'][^>]*>(.*?)</a>",
                RegexOptions.IgnoreCase | RegexOptions.Singleline))
            {
                string href = m.Groups[1].Value;
                string label = Regex.Replace(m.Groups[2].Value, "<.*?>", "").Trim();
                var lm = Regex.Match(label, @"(?:https?://)?([a-z0-9\-.]+\.[a-z]{2,})", RegexOptions.IgnoreCase);
                if (!lm.Success) continue;

                string labelHost = GetRegistrableDomain(lm.Groups[1].Value.ToLowerInvariant());
                string realHost = "";
                Uri u;
                if (Uri.TryCreate(href, UriKind.Absolute, out u)) realHost = GetRegistrableDomain(u.Host.ToLowerInvariant());

                if (!string.IsNullOrEmpty(realHost) && !string.IsNullOrEmpty(labelHost) &&
                    !labelHost.Equals(realHost, StringComparison.OrdinalIgnoreCase))
                {
                    Add(v, "リンクの表示と実際のあて先が違う",
                        "画面には " + labelHost + " と表示されますが、実際は " + realHost + " へ飛びます。", 35);
                }
            }

            // 宛名がない一般的な呼びかけ
            if (Regex.IsMatch(text, @"(お客様各位|ユーザー様|Dear Customer|Dear User)", RegexOptions.IgnoreCase))
                Add(v, "宛名が一般的", "契約者名ではなく「お客様」などの一般的な宛名です。一斉送信の可能性があります。", 8);

            v.Score = Math.Min(100, v.Signals.Sum(s => s.Score));
            return v;
        }

        // ==================================================================
        // 補助
        // ==================================================================
        private static void Add(UrlVerdict v, string name, string detail, int score)
        {
            v.Signals.Add(new UrlSignal { Name = name, Detail = detail, Score = score });
        }

        private static string Trim(string s, int n)
        {
            s = s.Replace("\r", " ").Replace("\n", " ");
            return s.Length <= n ? s : s.Substring(0, n) + "…";
        }

        private static bool IsOfficial(string host)
        {
            foreach (string b in KnownBrands)
            {
                if (host.Equals(b, StringComparison.OrdinalIgnoreCase) ||
                    host.EndsWith("." + b, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }

        public static string GetRegistrableDomain(string host)
        {
            if (string.IsNullOrEmpty(host)) return "";
            string[] p = host.Split('.');
            if (p.Length < 2) return host;

            string last2 = p[p.Length - 2] + "." + p[p.Length - 1];
            foreach (string suf in MultiLevelSuffixes)
            {
                if (last2.Equals(suf, StringComparison.OrdinalIgnoreCase))
                    return p.Length >= 3 ? p[p.Length - 3] + "." + last2 : last2;
            }
            return last2;
        }

        private static string FindTyposquat(string registrable)
        {
            if (string.IsNullOrEmpty(registrable)) return null;
            foreach (string b in KnownBrands)
            {
                if (registrable.Equals(b, StringComparison.OrdinalIgnoreCase)) return null;
                int d = Levenshtein(registrable, b);
                if (d > 0 && d <= 2 && Math.Abs(registrable.Length - b.Length) <= 2) return b;
            }
            return null;
        }

        private static bool HasMixedScript(string host)
        {
            bool latin = false, cyrillic = false, greek = false;
            foreach (char c in host)
            {
                if (c >= 'a' && c <= 'z') latin = true;
                else if (c >= 0x0400 && c <= 0x04FF) cyrillic = true;
                else if (c >= 0x0370 && c <= 0x03FF) greek = true;
            }
            return latin && (cyrillic || greek);
        }

        public static int Levenshtein(string a, string b)
        {
            if (string.IsNullOrEmpty(a)) return (b ?? "").Length;
            if (string.IsNullOrEmpty(b)) return a.Length;

            int[] prev = new int[b.Length + 1];
            int[] cur = new int[b.Length + 1];
            for (int j = 0; j <= b.Length; j++) prev[j] = j;

            for (int i = 1; i <= a.Length; i++)
            {
                cur[0] = i;
                for (int j = 1; j <= b.Length; j++)
                {
                    int cost = a[i - 1] == b[j - 1] ? 0 : 1;
                    cur[j] = Math.Min(Math.Min(cur[j - 1] + 1, prev[j] + 1), prev[j - 1] + cost);
                }
                var tmp = prev; prev = cur; cur = tmp;
            }
            return prev[b.Length];
        }
    }
}
