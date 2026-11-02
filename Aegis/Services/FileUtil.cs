using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Aegis.Services
{
    public static class FileUtil
    {
        /// <summary>SHA-256を計算（失敗時はnull）</summary>
        public static string Sha256(string path)
        {
            try
            {
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 65536))
                using (var sha = SHA256.Create())
                {
                    byte[] hash = sha.ComputeHash(fs);
                    var sb = new StringBuilder(hash.Length * 2);
                    foreach (byte b in hash) sb.Append(b.ToString("x2"));
                    return sb.ToString();
                }
            }
            catch
            {
                return null;
            }
        }

        /// <summary>先頭バイトを読む（読めない場合は空配列）</summary>
        public static byte[] ReadHead(string path, int count)
        {
            try
            {
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    int len = (int)Math.Min(count, fs.Length);
                    byte[] buf = new byte[len];
                    int read = 0;
                    while (read < len)
                    {
                        int n = fs.Read(buf, read, len - read);
                        if (n <= 0) break;
                        read += n;
                    }
                    if (read != len) Array.Resize(ref buf, read);
                    return buf;
                }
            }
            catch
            {
                return new byte[0];
            }
        }

        /// <summary>MZ/PEヘッダを持つ実行ファイルか</summary>
        public static bool IsPortableExecutable(byte[] head)
        {
            return head != null && head.Length >= 2 && head[0] == 0x4D && head[1] == 0x5A; // "MZ"
        }

        /// <summary>ZIP（Officeの新形式やJARを含む）か</summary>
        public static bool IsZipContainer(byte[] head)
        {
            return head != null && head.Length >= 4 &&
                   head[0] == 0x50 && head[1] == 0x4B &&
                   (head[2] == 0x03 || head[2] == 0x05 || head[2] == 0x07);
        }

        /// <summary>OLE複合ドキュメント（旧Office形式）か</summary>
        public static bool IsOleCompound(byte[] head)
        {
            byte[] sig = { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 };
            if (head == null || head.Length < sig.Length) return false;
            for (int i = 0; i < sig.Length; i++) if (head[i] != sig[i]) return false;
            return true;
        }

        /// <summary>シャノンエントロピー（0〜8）。暗号化・パッキングの目安</summary>
        public static double Entropy(byte[] data)
        {
            if (data == null || data.Length == 0) return 0;
            int[] freq = new int[256];
            foreach (byte b in data) freq[b]++;
            double e = 0;
            foreach (int f in freq)
            {
                if (f == 0) continue;
                double p = (double)f / data.Length;
                e -= p * Math.Log(p, 2);
            }
            return e;
        }

        /// <summary>Authenticode署名の有無と署名者名を返す</summary>
        public static bool TryGetSigner(string path, out string signer)
        {
            signer = null;
            try
            {
                using (X509Certificate cert = X509Certificate.CreateFromSignedFile(path))
                {
                    string subject = cert.Subject ?? "";
                    var m = System.Text.RegularExpressions.Regex.Match(subject, @"CN=([^,]+)");
                    signer = m.Success ? m.Groups[1].Value.Trim().Trim('"') : subject;
                    return true;
                }
            }
            catch
            {
                return false;
            }
        }

        /// <summary>Mark-of-the-Web（Zone.Identifier代替データストリーム）の有無</summary>
        public static bool HasMarkOfTheWeb(string path)
        {
            try
            {
                using (var fs = new FileStream(path + ":Zone.Identifier:$DATA", FileMode.Open, FileAccess.Read))
                {
                    return fs.Length > 0;
                }
            }
            catch
            {
                return false;
            }
        }

        /// <summary>テキストとして読み取り（先頭maxBytesまで）</summary>
        public static string ReadTextHead(string path, int maxBytes)
        {
            byte[] head = ReadHead(path, maxBytes);
            if (head.Length == 0) return "";
            try
            {
                // UTF-16LE BOM
                if (head.Length >= 2 && head[0] == 0xFF && head[1] == 0xFE)
                    return Encoding.Unicode.GetString(head);
                return Encoding.UTF8.GetString(head);
            }
            catch
            {
                return "";
            }
        }

        public static string Ext(string path)
        {
            try { return (Path.GetExtension(path) ?? "").ToLowerInvariant(); }
            catch { return ""; }
        }
    }
}
