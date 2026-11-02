using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using Aegis.Models;
using Aegis.Services;

namespace Aegis.Views
{
    /// <summary>ClamAV の定義更新と検査（旧 VirusScannerApp）。</summary>
    public partial class ClamAvView : UserControl
    {
        private readonly ObservableCollection<Detection> _hits = new ObservableCollection<Detection>();
        private ClamAvEngine _engine;
        private CancellationTokenSource _cts;

        public ClamAvView()
        {
            InitializeComponent();
            HitGrid.ItemsSource = _hits;
            Loaded += async (s, e) => { if (_engine == null) await RefreshEngineAsync(); };
        }

        private Window Owner { get { return Window.GetWindow(this); } }

        // ---------------------------------------------------------------- エンジンの状態

        private async Task RefreshEngineAsync()
        {
            _engine = ClamAvService.Locate();
            if (_engine == null)
            {
                EngineText.Text = "ClamAV が見つかりません。Aegis.exe と同じフォルダーの「ClamAV」に置くか、「ClamAV の場所を選ぶ…」で clamscan.exe のあるフォルダーを指定してください。";
                DbStateText.Text = "";
                SetBusy(false);
                return;
            }

            EngineText.Text = "エンジン: " + _engine.Folder;
            DbStateText.Text = "定義ファイル: " + _engine.DatabaseDir + (_engine.HasDatabase ? "" : "（まだありません。「定義ファイルを更新」を押してください）");
            SetBusy(false);
            try
            {
                string v = await ClamAvService.GetVersionAsync(_engine);
                if (!string.IsNullOrEmpty(v)) EngineText.Text += "　（" + v + "）";
            }
            catch (Exception ex) { Log("版を確認できませんでした: " + ex.Message); }
        }

        private async void Choose_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new Microsoft.Win32.OpenFolderDialog { Title = "clamscan.exe と freshclam.exe のあるフォルダーを選ぶ" };
            if (dlg.ShowDialog(Owner) != true) return;
            var chosen = ClamAvService.Choose(dlg.FolderName);
            if (chosen == null)
            {
                MessageBox.Show(Owner, "そのフォルダーには clamscan.exe と freshclam.exe がありません。", "Aegis",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            await RefreshEngineAsync();
        }

        // ---------------------------------------------------------------- 定義の更新

        private async void Update_Click(object sender, RoutedEventArgs e)
        {
            if (_engine == null) { await RefreshEngineAsync(); if (_engine == null) return; }
            if (!_engine.HasDatabase && MessageBox.Show(Owner,
                    "ClamAV の定義ファイルをインターネット（database.clamav.net）から取得します。\n初回はおよそ 300 MB あり、数分かかります。\n\n続けますか？",
                    "定義ファイルの取得", MessageBoxButton.OKCancel, MessageBoxImage.Question) != MessageBoxResult.OK)
                return;

            _cts = new CancellationTokenSource();
            SetBusy(true);
            Progress.IsIndeterminate = true;
            ProgressText.Text = "定義ファイルを更新しています…";
            Log("── 定義ファイルの更新 ──");
            try
            {
                int code = await ClamAvService.UpdateAsync(_engine, line => Dispatcher.BeginInvoke(new Action(() => Log(line))), _cts.Token);
                ProgressText.Text = code == 0 ? "定義ファイルを更新しました。" : $"更新は終了コード {code} で終わりました（ログを確認してください）。";
                AppLog.Info("ClamAV 定義更新: 終了コード " + code);
            }
            catch (OperationCanceledException) { ProgressText.Text = "更新を中止しました。"; }
            catch (Exception ex) { ProgressText.Text = "更新できませんでした: " + ex.Message; AppLog.Warn("ClamAV 定義更新に失敗: " + ex.Message); }
            finally
            {
                Progress.IsIndeterminate = false;
                _cts.Dispose(); _cts = null;
                await RefreshEngineAsync();
            }
        }

        // ---------------------------------------------------------------- 検査

        private async void Scan_Click(object sender, RoutedEventArgs e)
        {
            if (_engine == null) { await RefreshEngineAsync(); if (_engine == null) return; }
            if (!_engine.HasDatabase)
            {
                MessageBox.Show(Owner, "ClamAV の定義ファイルがありません。先に「定義ファイルを更新」を押してください。", "Aegis",
                    MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            var dlg = new Microsoft.Win32.OpenFolderDialog { Title = "ClamAV で検査するフォルダーを選ぶ" };
            if (dlg.ShowDialog(Owner) != true) return;
            await ScanFolderAsync(dlg.FolderName);
        }

        public async Task ScanFolderAsync(string folder)
        {
            _cts = new CancellationTokenSource();
            SetBusy(true);
            Progress.IsIndeterminate = true;
            ProgressText.Text = "検査しています…";
            Log("── ClamAV で検査: " + folder + " ──");
            var started = DateTime.Now;
            int lastShown = 0;

            try
            {
                var r = await ClamAvService.ScanAsync(_engine, folder,
                    line => Dispatcher.BeginInvoke(new Action(() => Log(line))),
                    n =>
                    {
                        // 画面の更新は 50 件ごとに間引く（旧 VirusScannerApp と同じ考え方）
                        if (n - lastShown < 50) return;
                        lastShown = n;
                        Dispatcher.BeginInvoke(new Action(() => ProgressText.Text = $"検査しています… {n:N0} 件"));
                    },
                    hit => Dispatcher.BeginInvoke(new Action(() => AddHit(hit))),
                    _cts.Token);

                string elapsed = (DateTime.Now - started).TotalSeconds.ToString("0.0");
                if (r.Canceled) ProgressText.Text = $"中止しました（{r.FilesScanned:N0} 件まで検査）。";
                else ProgressText.Text = r.Hits.Count == 0
                    ? $"{r.FilesScanned:N0} 件を検査しました。検出はありません（{elapsed} 秒）。"
                    : $"{r.FilesScanned:N0} 件を検査し、{r.Hits.Count} 件を検出しました（{elapsed} 秒）。下の一覧から隔離できます。";
                foreach (string s in r.Summary) Log(s);
                MainWindow.Instance?.SetStatus("ClamAV: " + ProgressText.Text);
                AppLog.Info($"ClamAV 検査 {folder}: {r.FilesScanned} 件・検出 {r.Hits.Count} 件・終了コード {r.ExitCode}");
            }
            catch (Exception ex)
            {
                ProgressText.Text = "検査できませんでした: " + ex.Message;
                AppLog.Warn("ClamAV 検査に失敗: " + ex.Message);
            }
            finally
            {
                Progress.IsIndeterminate = false;
                SetBusy(false);
                _cts.Dispose(); _cts = null;
            }
        }

        private void AddHit(ClamAvHit hit)
        {
            long size = 0;
            try { size = new FileInfo(hit.FilePath).Length; } catch { }
            _hits.Add(new Detection
            {
                FilePath = hit.FilePath,
                FileName = Path.GetFileName(hit.FilePath),
                RuleId = "ClamAV",
                RuleName = hit.Signature,
                Description = "ClamAV の定義に一致しました",
                Level = ThreatLevel.High,
                Size = size,
                DetectedAt = DateTime.Now
            });
        }

        private void Cancel_Click(object sender, RoutedEventArgs e)
        {
            _cts?.Cancel();
            ProgressText.Text = "中止しています…";
        }

        // ---------------------------------------------------------------- 検出への対処

        private void Quarantine_Click(object sender, RoutedEventArgs e)
        {
            var selected = HitGrid.SelectedItems.Cast<Detection>().ToList();
            if (selected.Count == 0) return;
            if (MessageBox.Show(Owner, $"{selected.Count} 件を隔離ボックスへ移します。元の場所からは消えます（隔離ボックスから元に戻せます）。",
                    "隔離", MessageBoxButton.OKCancel, MessageBoxImage.Question) != MessageBoxResult.OK) return;

            int ok = 0;
            foreach (var d in selected)
            {
                try
                {
                    AppState.Quarantine.Quarantine(d);
                    _hits.Remove(d);
                    ok++;
                }
                catch (Exception ex) { Log("隔離できませんでした: " + d.FilePath + " — " + ex.Message); }
            }
            Log($"{ok} 件を隔離しました。");
        }

        private void Reveal_Click(object sender, RoutedEventArgs e)
        {
            if (HitGrid.SelectedItem is Detection d) AppState.OpenInExplorer(d.FilePath);
        }

        // ---------------------------------------------------------------- 表示

        private void SetBusy(bool busy)
        {
            bool ready = !busy && _engine != null;
            ScanButton.IsEnabled = ready;
            UpdateButton.IsEnabled = ready;
            ChooseButton.IsEnabled = !busy;
            CancelButton.IsEnabled = busy;
        }

        private void Log(string line)
        {
            LogBox.AppendText(DateTime.Now.ToString("HH:mm:ss") + "  " + line + Environment.NewLine);
            LogBox.ScrollToEnd();
        }
    }
}
