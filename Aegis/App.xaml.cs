using System;
using System.Windows;
using System.Windows.Threading;

namespace Aegis
{
    public partial class App : Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);
            DispatcherUnhandledException += OnDispatcherUnhandledException;
            AppDomain.CurrentDomain.UnhandledException += (s, args) =>
            {
                Services.AppLog.Error("未処理例外: " + args.ExceptionObject);
            };
        }

        private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
        {
            Services.AppLog.Error("UI例外: " + e.Exception);
            MessageBox.Show(
                "処理中にエラーが発生しました。\n\n" + e.Exception.Message,
                "Aegis", MessageBoxButton.OK, MessageBoxImage.Warning);
            e.Handled = true;
        }
    }
}
