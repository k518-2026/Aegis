using System;
using System.IO;
using System.Text;

namespace Aegis.Services
{
    /// <summary>アプリ全体のログとデータフォルダ管理</summary>
    public static class AppLog
    {
        private static readonly object _lock = new object();

        /// <summary>%LOCALAPPDATA%\Aegis</summary>
        public static string DataDir
        {
            get
            {
                string dir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Aegis");
                Directory.CreateDirectory(dir);
                return dir;
            }
        }

        public static string LogPath { get { return Path.Combine(DataDir, "aegis.log"); } }

        public static void Info(string message) { Write("INFO", message); }
        public static void Warn(string message) { Write("WARN", message); }
        public static void Error(string message) { Write("ERROR", message); }

        private static void Write(string level, string message)
        {
            try
            {
                lock (_lock)
                {
                    File.AppendAllText(LogPath,
                        string.Format("{0:yyyy-MM-dd HH:mm:ss} [{1}] {2}{3}",
                            DateTime.Now, level, message, Environment.NewLine),
                        Encoding.UTF8);
                }
            }
            catch
            {
                // ログ書き込み失敗はアプリを止めない
            }
        }
    }
}
