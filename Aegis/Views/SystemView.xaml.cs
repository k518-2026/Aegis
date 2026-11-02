using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using Aegis.Models;
using Aegis.Services;
using Microsoft.Win32;

namespace Aegis.Views
{
    public partial class SystemView : UserControl
    {
        public ObservableCollection<SystemCheckItem> Checks { get; } = new ObservableCollection<SystemCheckItem>();

        public SystemView()
        {
            InitializeComponent();
            DataContext = this;
        }

        private async void Run_Click(object sender, RoutedEventArgs e)
        {
            RunButton.IsEnabled = false;
            SummaryText.Text = "診断中です…";
            Checks.Clear();

            try
            {
                List<SystemCheckItem> items = await new SystemInspector().InspectAsync();

                // 危険 → 注意 → 不明 → 良好 の順に並べる
                foreach (var i in items.OrderBy(x => Rank(x.Status)).ThenBy(x => x.Category))
                    Checks.Add(i);

                int danger = items.Count(x => x.Status == CheckStatus.Danger);
                int warn = items.Count(x => x.Status == CheckStatus.Warn);
                int ok = items.Count(x => x.Status == CheckStatus.Ok);

                SummaryText.Text = string.Format("危険 {0} 件 / 注意 {1} 件 / 良好 {2} 件（全 {3} 項目）",
                    danger, warn, ok, items.Count);

                if (!AppState.IsAdministrator)
                    SummaryText.Text += "　※管理者として実行すると取得できる項目が増えます。";

                if (MainWindow.Instance != null) MainWindow.Instance.SetStatus(SummaryText.Text);
            }
            catch (Exception ex)
            {
                AppLog.Error("診断失敗: " + ex);
                SummaryText.Text = "診断中にエラーが発生しました: " + ex.Message;
            }
            finally
            {
                RunButton.IsEnabled = true;
            }
        }

        private static int Rank(CheckStatus s)
        {
            switch (s)
            {
                case CheckStatus.Danger: return 0;
                case CheckStatus.Warn: return 1;
                case CheckStatus.Unknown: return 2;
                default: return 3;
            }
        }

        private void CheckGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            var c = CheckGrid.SelectedItem as SystemCheckItem;
            if (c == null) return;
            AdviceTitle.Text = c.Name + "（" + c.StatusText + "）";
            AdviceDetail.Text = c.Detail;
            AdviceText.Text = string.IsNullOrWhiteSpace(c.Advice)
                ? "この項目は問題ありません。対処は不要です。"
                : c.Advice;
        }

        private void OpenSecurity_Click(object sender, RoutedEventArgs e)
        {
            AppState.OpenPath("windowsdefender://");
        }

        private void Export_Click(object sender, RoutedEventArgs e)
        {
            if (Checks.Count == 0) { MessageBox.Show("先に診断を実行してください。", "Aegis"); return; }

            var dlg = new SaveFileDialog
            {
                Filter = "HTMLファイル (*.html)|*.html",
                FileName = "aegis-system-" + DateTime.Now.ToString("yyyyMMdd-HHmm") + ".html"
            };
            if (dlg.ShowDialog() != true) return;

            ReportExporter.ExportScanHtml(dlg.FileName, null, Checks.ToList());
            if (MessageBox.Show("保存しました。開きますか？", "Aegis",
                    MessageBoxButton.YesNo) == MessageBoxResult.Yes)
                AppState.OpenPath(dlg.FileName);
        }
    }
}
