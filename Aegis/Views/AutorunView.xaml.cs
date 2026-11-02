using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using Aegis.Models;
using Aegis.Services;

namespace Aegis.Views
{
    public partial class AutorunView : UserControl
    {
        public ObservableCollection<AutorunItem> Items { get; } = new ObservableCollection<AutorunItem>();

        public AutorunView()
        {
            InitializeComponent();
            DataContext = this;
        }

        private async void Run_Click(object sender, RoutedEventArgs e)
        {
            RunButton.IsEnabled = false;
            SummaryText.Text = "取得中です…";
            Items.Clear();

            try
            {
                List<AutorunItem> list = await new AutorunInspector().InspectAsync();
                foreach (var i in list.OrderByDescending(x => x.Level).ThenBy(x => x.Source)) Items.Add(i);

                int attention = list.Count(x => x.Level >= ThreatLevel.Medium);
                SummaryText.Text = string.Format("{0} 件の自動起動項目が見つかりました（うち要確認 {1} 件）。",
                    list.Count, attention);
                if (MainWindow.Instance != null) MainWindow.Instance.SetStatus(SummaryText.Text);
            }
            catch (Exception ex)
            {
                SummaryText.Text = "取得に失敗しました: " + ex.Message;
            }
            finally
            {
                RunButton.IsEnabled = true;
            }
        }

        private void ScanItem_Click(object sender, RoutedEventArgs e)
        {
            var item = Grid1.SelectedItem as AutorunItem;
            if (item == null || string.IsNullOrEmpty(item.ResolvedPath)) return;

            if (!File.Exists(item.ResolvedPath))
            {
                MessageBox.Show("実体のファイルが見つかりません。\n" + item.ResolvedPath, "Aegis");
                return;
            }

            var heur = new HeuristicEngine { DeepInspection = true };
            var results = heur.Inspect(new FileInfo(item.ResolvedPath));

            string hash = FileUtil.Sha256(item.ResolvedPath);
            SignatureEntry entry;
            if (hash != null && AppState.Signatures.TryMatch(hash, out entry))
            {
                results.Insert(0, new Detection
                {
                    RuleName = "定義ファイル一致: " + entry.Name,
                    Level = SignatureDatabase.ParseLevel(entry.Level),
                    Description = entry.Note
                });
            }

            string body = results.Count == 0
                ? "特に問題は見つかりませんでした。"
                : string.Join("\n\n", results.Select(r => "■ " + r.LevelText + "　" + r.RuleName + "\n" + r.Description));

            MessageBox.Show(item.Name + "\n" + item.ResolvedPath + "\n\nSHA-256: " + (hash ?? "-") + "\n\n" + body,
                "検査結果", MessageBoxButton.OK,
                results.Any(r => r.Level >= ThreatLevel.High) ? MessageBoxImage.Warning : MessageBoxImage.Information);
        }

        private void Reveal_Click(object sender, RoutedEventArgs e)
        {
            var item = Grid1.SelectedItem as AutorunItem;
            if (item != null && !string.IsNullOrEmpty(item.ResolvedPath))
                AppState.OpenInExplorer(item.ResolvedPath);
        }

        private void Remove_Click(object sender, RoutedEventArgs e)
        {
            var item = Grid1.SelectedItem as AutorunItem;
            if (item == null) return;

            if (MessageBox.Show(
                    "次の項目を自動起動から外します。\n\n" + item.Name + "\n" + item.Command +
                    "\n\nプログラム本体は削除されません。続行しますか？",
                    "Aegis", MessageBoxButton.OKCancel, MessageBoxImage.Question) != MessageBoxResult.OK) return;

            try
            {
                AutorunInspector.RemoveRunEntry(item);
                Items.Remove(item);
                MessageBox.Show("自動起動から外しました。", "Aegis");
            }
            catch (UnauthorizedAccessException)
            {
                MessageBox.Show("権限が足りません。「管理者として実行」してから、もう一度お試しください。", "Aegis");
            }
            catch (Exception ex)
            {
                MessageBox.Show("削除に失敗しました。\n" + ex.Message, "Aegis");
            }
        }
    }
}
