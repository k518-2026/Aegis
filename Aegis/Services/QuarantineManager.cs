using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;
using Aegis.Models;

namespace Aegis.Services
{
    /// <summary>
    /// 検出したファイルを隔離フォルダへ退避します。
    /// 保存時に全バイトをXOR変換するため、隔離中のファイルはそのままでは実行できません。
    /// （暗号化ではなく、誤って起動しないようにするための無害化です）
    /// </summary>
    public class QuarantineManager
    {
        private const byte XorKey = 0x5A;

        public string QuarantineDir
        {
            get
            {
                string dir = Path.Combine(AppLog.DataDir, "Quarantine");
                Directory.CreateDirectory(dir);
                return dir;
            }
        }

        public List<QuarantineItem> LoadAll()
        {
            var list = new List<QuarantineItem>();
            try
            {
                foreach (string meta in Directory.EnumerateFiles(QuarantineDir, "*.json"))
                {
                    try
                    {
                        var item = JsonSerializer.Deserialize<QuarantineItem>(File.ReadAllText(meta));
                        if (item != null) list.Add(item);
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                AppLog.Error("隔離一覧の読み込みに失敗: " + ex.Message);
            }
            list.Sort((a, b) => b.QuarantinedAt.CompareTo(a.QuarantinedAt));
            return list;
        }

        /// <summary>ファイルを隔離する</summary>
        public QuarantineItem Quarantine(Detection d)
        {
            if (!File.Exists(d.FilePath))
                throw new FileNotFoundException("対象のファイルが見つかりません。", d.FilePath);

            var fi = new FileInfo(d.FilePath);
            string id = DateTime.Now.ToString("yyyyMMddHHmmssfff") + "_" + Guid.NewGuid().ToString("N").Substring(0, 8);
            string binPath = Path.Combine(QuarantineDir, id + ".qbin");
            string metaPath = Path.Combine(QuarantineDir, id + ".json");

            using (var src = new FileStream(d.FilePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            using (var dst = new FileStream(binPath, FileMode.CreateNew, FileAccess.Write))
            {
                byte[] buf = new byte[81920];
                int n;
                while ((n = src.Read(buf, 0, buf.Length)) > 0)
                {
                    for (int i = 0; i < n; i++) buf[i] ^= XorKey;
                    dst.Write(buf, 0, n);
                }
            }

            var item = new QuarantineItem
            {
                Id = id,
                OriginalPath = d.FilePath,
                FileName = fi.Name,
                Sha256 = string.IsNullOrEmpty(d.Sha256) ? (FileUtil.Sha256(d.FilePath) ?? "") : d.Sha256,
                Size = fi.Length,
                RuleName = d.RuleName,
                Level = d.Level.ToString(),
                QuarantinedAt = DateTime.Now
            };

            File.WriteAllText(metaPath,
                JsonSerializer.Serialize(item, new JsonSerializerOptions { WriteIndented = true }),
                Encoding.UTF8);

            try
            {
                File.SetAttributes(d.FilePath, FileAttributes.Normal);
                File.Delete(d.FilePath);
            }
            catch (Exception ex)
            {
                // 元ファイルを消せなかった場合は隔離を取り消す
                try { File.Delete(binPath); } catch { }
                try { File.Delete(metaPath); } catch { }
                throw new IOException(
                    "元のファイルを移動できませんでした。使用中か、管理者権限が必要な可能性があります。\n" + ex.Message, ex);
            }

            AppLog.Info("隔離: " + d.FilePath);
            return item;
        }

        /// <summary>隔離を解除して元の場所へ戻す</summary>
        public void Restore(QuarantineItem item, string overridePath = null)
        {
            string binPath = Path.Combine(QuarantineDir, item.Id + ".qbin");
            if (!File.Exists(binPath))
                throw new FileNotFoundException("隔離データが見つかりません。", binPath);

            string target = string.IsNullOrEmpty(overridePath) ? item.OriginalPath : overridePath;
            string dir = Path.GetDirectoryName(target);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

            if (File.Exists(target))
                target = Path.Combine(dir ?? "",
                    Path.GetFileNameWithoutExtension(target) + "_restored" + Path.GetExtension(target));

            using (var src = new FileStream(binPath, FileMode.Open, FileAccess.Read))
            using (var dst = new FileStream(target, FileMode.CreateNew, FileAccess.Write))
            {
                byte[] buf = new byte[81920];
                int n;
                while ((n = src.Read(buf, 0, buf.Length)) > 0)
                {
                    for (int i = 0; i < n; i++) buf[i] ^= XorKey;
                    dst.Write(buf, 0, n);
                }
            }

            DeleteEntry(item);
            AppLog.Info("復元: " + target);
        }

        /// <summary>隔離データを完全に削除する</summary>
        public void DeletePermanently(QuarantineItem item)
        {
            DeleteEntry(item);
            AppLog.Info("完全削除: " + item.FileName);
        }

        private void DeleteEntry(QuarantineItem item)
        {
            string binPath = Path.Combine(QuarantineDir, item.Id + ".qbin");
            string metaPath = Path.Combine(QuarantineDir, item.Id + ".json");
            try { if (File.Exists(binPath)) File.Delete(binPath); } catch { }
            try { if (File.Exists(metaPath)) File.Delete(metaPath); } catch { }
        }
    }
}
