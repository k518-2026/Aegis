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
    public partial class MonitorView : UserControl
    {
        public ObservableCollection<Detection> Events { get; } = new ObservableCollection<Detection>();

        private RealtimeMonitor _monitor;

        public MonitorView()
        {
            InitializeComponent();
            DataContext = this;

            foreach (string d in RealtimeMonitor.DefaultFolders()) FolderList.Items.Add(d);
        }

        private void Start_Click(object sender, RoutedEventArgs e)
        {
            var folders = FolderList.Items.Cast<object>().Select(o => o.ToString()).ToList();
            if (folders.Count == 0)
            {
                MessageBox.Show("監視するフォルダを追加してください。", "Aegis");
                return;
            }

            _monitor = new RealtimeMonitor(AppState.Signatures);
            _monitor.Detected += OnDetected;
            _monitor.Start(folders);

            StartButton.IsEnabled = false;
            StopButton.IsEnabled = true;
            MonitorStatus.Text = "監視中（" + folders.Count + " フォルダ）";
            if (MainWindow.Instance != null) MainWindow.Instance.SetStatus("リアルタイム監視を開始しました。");
        }

        private void Stop_Click(object sender, RoutedEventArgs e)
        {
            StopMonitor();
            MonitorStatus.Text = "停止中";
            StartButton.IsEnabled = true;
            StopButton.IsEnabled = false;
        }

        public void StopMonitor()
        {
            if (_monitor == null) return;
            _monitor.Detected -= OnDetected;
            _monitor.Dispose();
            _monitor = null;
        }

        private void OnDetected(Detection d)
        {
            Dispatcher.BeginInvoke(new Action(() =>
            {
                Events.Insert(0, d);
                while (Events.Count > 500) Events.RemoveAt(Events.Count - 1);

                if (MainWindow.Instance != null)
                    MainWindow.Instance.SetStatus("検出: " + d.FileName + "（" + d.RuleName + "）");

                if (AutoQuarantineCheck.IsChecked == true && d.Level >= ThreatLevel.High)
                {
                    try
                    {
                        AppState.Quarantine.Quarantine(d);
                        MainWindow.Instance?.SetStatus("自動隔離しました: " + d.FileName);
                    }
                    catch (Exception ex)
                    {
                        AppLog.Warn("自動隔離に失敗: " + ex.Message);
                    }
                }
                else if (d.Level >= ThreatLevel.High)
                {
                    MessageBox.Show(
                        "新しいファイルに問題が見つかりました。\n\n" +
                        d.FileName + "\n" + d.RuleName + "\n\n" + d.Description,
                        "Aegis - 警告", MessageBoxButton.OK, MessageBoxImage.Warning);
                }
            }));
        }

        private void AddFolder_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new OpenFolderDialog { Title = "監視するフォルダを選んでください" };
            if (dlg.ShowDialog() == true && !FolderList.Items.Contains(dlg.FolderName))
                FolderList.Items.Add(dlg.FolderName);
        }

        private void RemoveFolder_Click(object sender, RoutedEventArgs e)
        {
            if (FolderList.SelectedItem != null) FolderList.Items.Remove(FolderList.SelectedItem);
        }
    }
}
