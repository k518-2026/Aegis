using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using Aegis.Models;
using Aegis.Services;
using Microsoft.Win32;

namespace Aegis.Views
{
    public partial class ScanView : UserControl
    {
        public ObservableCollection<Detection> Detections { get; } = new ObservableCollection<Detection>();

        private CancellationTokenSource _cts;
        private ScanSummary _lastSummary;

        public ScanView()
        {
            InitializeComponent();
            DataContext = this;
        }

        // ------------------------------------------------------------------
        private void QuickScan_Click(object sender, RoutedEventArgs e)
        {
            var targets = FileScanner.QuickScanTargets();
            if (targets.Count == 0)
            {
                MessageBox.Show("検査対象のフォルダが見つかりませんでした。", "Aegis");
                return;
            }
            StartScan(targets);
        }

        private void FolderScan_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new OpenFolderDialog { Title = "検査するフォルダを選んでください" };
            if (dlg.ShowDialog() == true) StartScan(new List<string> { dlg.FolderName });
        }

        private void FileScan_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new OpenFileDialog { Title = "検査するファイルを選んでください", Multiselect = true };
            if (dlg.ShowDialog() == true) StartScan(dlg.FileNames.ToList());
        }

        private void DriveScan_Click(object sender, RoutedEventArgs e)
        {
            var drives = DriveInfo.GetDrives()
                .Where(d => d.IsReady && (d.DriveType == DriveType.Fixed || d.DriveType == DriveType.Removable))
                .Select(d => d.RootDirectory.FullName).ToList();

            if (drives.Count == 0) return;

            var res = MessageBox.Show(
                "次のドライブ全体を検査します。時間がかかります。\n\n" + string.Join("\n", drives),
                "Aegis", MessageBoxButton.OKCancel, MessageBoxImage.Question);
            if (res == MessageBoxResult.OK) StartScan(drives);
        }

        private void Cancel_Click(object sender, RoutedEventArgs e)
        {
            if (_cts != null) _cts.Cancel();
            ProgressText.Text = "中止しています…";
        }

        // ------------------------------------------------------------------
        private async void StartScan(List<string> targets)
        {
            if (_cts != null) return;

            Detections.Clear();
            _cts = new CancellationTokenSource();
            SetBusy(true);

            var opt = new ScanOptions
            {
                UseHeuristics = HeuristicCheck.IsChecked == true,
                DeepInspection = DeepCheck.IsChecked == true,
                IncludeSubFolders = SubFolderCheck.IsChecked == true,
                ReportInfoLevel = InfoCheck.IsChecked == true
            };

            var scanner = new FileScanner(AppState.Signatures);
            var progress = new Progress<ScanProgress>(p =>
            {
                ScanBar.Value = p.Percent;
                ProgressText.Text = string.Format("{0} / {1} 件を検査中　検出 {2} 件　{3}",
                    p.FilesScanned, p.FilesTotal, p.DetectionCount, p.CurrentFile);
            });

            var pending = new List<Detection>();
            Action<Detection> onDetect = d =>
            {
                lock (pending) pending.Add(d);
                Dispatcher.BeginInvoke(new Action(() =>
                {
                    List<Detection> take;
                    lock (pending) { take = new List<Detection>(pending); pending.Clear(); }
                    foreach (var x in take) Detections.Add(x);
                }));
            };

            try
            {
                ProgressText.Text = "対象を数えています…";
                _lastSummary = await scanner.ScanAsync(targets, opt, progress, onDetect, _cts.Token);

                ScanBar.Value = 100;
                string msg = _lastSummary.Canceled ? "検査を中止しました。" : "検査が完了しました。";
                ProgressText.Text = string.Format("{0}　検査 {1} 件 / 検出 {2} 件 / 所要 {3}",
                    msg, _lastSummary.FilesScanned, _lastSummary.Detections.Count,
                    _lastSummary.Elapsed.ToString(@"mm\:ss"));

                if (MainWindow.Instance != null) MainWindow.Instance.SetStatus(ProgressText.Text);

                if (!_lastSummary.Canceled && _lastSummary.Detections.Count == 0)
                    MessageBox.Show("問題のあるファイルは見つかりませんでした。", "Aegis",
                        MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (OperationCanceledException)
            {
                ProgressText.Text = "検査を中止しました。";
            }
            catch (Exception ex)
            {
                AppLog.Error("スキャン失敗: " + ex);
                MessageBox.Show("検査中にエラーが発生しました。\n" + ex.Message, "Aegis",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
            }
            finally
            {
                _cts.Dispose();
                _cts = null;
                SetBusy(false);
            }
        }

        private void SetBusy(bool busy)
        {
            QuickScanButton.IsEnabled = !busy;
            FolderScanButton.IsEnabled = !busy;
            FileScanButton.IsEnabled = !busy;
            DriveScanButton.IsEnabled = !busy;
            CancelButton.IsEnabled = busy;
        }

        // ------------------------------------------------------------------
        private void ResultGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            var d = ResultGrid.SelectedItem as Detection;
            if (d == null) return;

            DetailName.Text = d.FileName;
            DetailLevel.Text = d.LevelText + "　/　" + d.RuleName + "（" + d.RuleId + "）";
            DetailDesc.Text = d.Description;
            DetailPath.Text = d.FilePath;
            DetailHash.Text = string.IsNullOrEmpty(d.Sha256) ? "（未計算）" : d.Sha256;
        }

        private void Quarantine_Click(object sender, RoutedEventArgs e)
        {
            var items = ResultGrid.SelectedItems.Cast<Detection>().ToList();
            if (items.Count == 0)
            {
                MessageBox.Show("隔離するファイルを一覧から選んでください。", "Aegis");
                return;
            }

            var res = MessageBox.Show(
                items.Count + " 件のファイルを隔離ボックスへ移動します。\n" +
                "元の場所からは削除されますが、隔離ボックスからいつでも戻せます。\n\n続行しますか？",
                "Aegis", MessageBoxButton.OKCancel, MessageBoxImage.Question);
            if (res != MessageBoxResult.OK) return;

            int ok = 0;
            var errors = new List<string>();
            foreach (var d in items.GroupBy(x => x.FilePath).Select(g => g.First()))
            {
                try
                {
                    AppState.Quarantine.Quarantine(d);
                    ok++;
                    foreach (var same in Detections.Where(x => x.FilePath == d.FilePath).ToList())
                        Detections.Remove(same);
                }
                catch (Exception ex)
                {
                    errors.Add(d.FileName + ": " + ex.Message);
                }
            }

            string text = ok + " 件を隔離しました。";
            if (errors.Count > 0) text += "\n\n失敗:\n" + string.Join("\n", errors.Take(5));
            MessageBox.Show(text, "Aegis");
        }

        private void Reveal_Click(object sender, RoutedEventArgs e)
        {
            var d = ResultGrid.SelectedItem as Detection;
            if (d != null) AppState.OpenInExplorer(d.FilePath);
        }

        private void AddSignature_Click(object sender, RoutedEventArgs e)
        {
            var d = ResultGrid.SelectedItem as Detection;
            if (d == null) return;

            string hash = string.IsNullOrEmpty(d.Sha256) ? FileUtil.Sha256(d.FilePath) : d.Sha256;
            if (string.IsNullOrEmpty(hash))
            {
                MessageBox.Show("ハッシュを計算できませんでした。", "Aegis");
                return;
            }

            SignatureDatabase.AppendUserSignature(hash, d.FileName, d.Level);
            AppState.Signatures.Load();
            MessageBox.Show("ユーザー定義に追加しました。\n次回以降は同じ内容のファイルを即座に検出します。\n\n" +
                            SignatureDatabase.UserSignaturePath, "Aegis");
        }

        private void ExportCsv_Click(object sender, RoutedEventArgs e)
        {
            if (Detections.Count == 0) { MessageBox.Show("出力する結果がありません。", "Aegis"); return; }

            var dlg = new SaveFileDialog
            {
                Filter = "CSVファイル (*.csv)|*.csv",
                FileName = "aegis-scan-" + DateTime.Now.ToString("yyyyMMdd-HHmm") + ".csv"
            };
            if (dlg.ShowDialog() != true) return;

            ReportExporter.ExportDetectionsCsv(dlg.FileName, Detections);
            MessageBox.Show("保存しました。", "Aegis");
        }

        private void ExportHtml_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new SaveFileDialog
            {
                Filter = "HTMLファイル (*.html)|*.html",
                FileName = "aegis-report-" + DateTime.Now.ToString("yyyyMMdd-HHmm") + ".html"
            };
            if (dlg.ShowDialog() != true) return;

            var summary = _lastSummary ?? new ScanSummary { StartedAt = DateTime.Now, FinishedAt = DateTime.Now };
            summary.Detections = Detections.ToList();

            List<SystemCheckItem> checks = null;
            try { checks = new SystemInspector().Inspect(); } catch { }

            ReportExporter.ExportScanHtml(dlg.FileName, summary, checks);
            if (MessageBox.Show("保存しました。開きますか？", "Aegis",
                    MessageBoxButton.YesNo) == MessageBoxResult.Yes)
                AppState.OpenPath(dlg.FileName);
        }

        private void Clear_Click(object sender, RoutedEventArgs e)
        {
            Detections.Clear();
            ProgressText.Text = "待機中";
            ScanBar.Value = 0;
        }
    }
}
