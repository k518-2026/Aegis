using System;
using System.Diagnostics;
using System.Security.Principal;

namespace Aegis.Services
{
    /// <summary>アプリ全体で共有するインスタンス</summary>
    public static class AppState
    {
        private static SignatureDatabase _db;
        private static QuarantineManager _quarantine;

        public static SignatureDatabase Signatures
        {
            get
            {
                if (_db == null)
                {
                    _db = new SignatureDatabase();
                    _db.Load();
                }
                return _db;
            }
        }

        public static QuarantineManager Quarantine
        {
            get
            {
                if (_quarantine == null) _quarantine = new QuarantineManager();
                return _quarantine;
            }
        }

        public static bool IsAdministrator
        {
            get
            {
                try
                {
                    using (var id = WindowsIdentity.GetCurrent())
                    {
                        return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
                    }
                }
                catch { return false; }
            }
        }

        /// <summary>管理者権限で自分自身を起動しなおす</summary>
        public static bool RestartAsAdmin()
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = Process.GetCurrentProcess().MainModule.FileName,
                    UseShellExecute = true,
                    Verb = "runas"
                };
                Process.Start(psi);
                return true;
            }
            catch (Exception ex)
            {
                AppLog.Warn("昇格に失敗: " + ex.Message);
                return false;
            }
        }

        public static void OpenInExplorer(string path)
        {
            try
            {
                Process.Start(new ProcessStartInfo("explorer.exe", "/select,\"" + path + "\"") { UseShellExecute = true });
            }
            catch (Exception ex)
            {
                AppLog.Warn("エクスプローラー起動に失敗: " + ex.Message);
            }
        }

        public static void OpenPath(string path)
        {
            try
            {
                Process.Start(new ProcessStartInfo(path) { UseShellExecute = true });
            }
            catch (Exception ex)
            {
                AppLog.Warn("起動に失敗: " + ex.Message);
            }
        }
    }
}
