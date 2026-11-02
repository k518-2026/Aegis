using System;
using System.Windows;
using Aegis.Services;

namespace Aegis
{
    public partial class MainWindow : Window
    {
        public static MainWindow Instance { get; private set; }

        public MainWindow()
        {
            InitializeComponent();
            Instance = this;
            Loaded += OnLoaded;
            Closed += OnClosed;
        }

        private void OnLoaded(object sender, RoutedEventArgs e)
        {
            var db = AppState.Signatures;
            DbText.Text = string.Format("ハッシュ定義 {0} 件（v{1} / {2}）", db.Count, db.Version, db.Updated);

            if (AppState.IsAdministrator)
            {
                AdminText.Text = "管理者として実行中";
                AdminButton.Visibility = Visibility.Collapsed;
            }
            else
            {
                AdminText.Text = "一部の診断には管理者権限が必要です";
            }

            AppLog.Info("Aegis を起動しました。");
        }

        private void OnClosed(object sender, EventArgs e)
        {
            try { MonitorPage.StopMonitor(); } catch { }
        }

        public void SetStatus(string text)
        {
            Dispatcher.Invoke(() => StatusText.Text = text);
        }

        private void AdminButton_Click(object sender, RoutedEventArgs e)
        {
            if (AppState.RestartAsAdmin()) Application.Current.Shutdown();
        }
    }
}
