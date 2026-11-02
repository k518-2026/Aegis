using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using Aegis.Models;
using Aegis.Services;
using Microsoft.Win32;

namespace Aegis.Views
{
    public partial class QuarantineView : UserControl
    {
        public ObservableCollection<QuarantineItem> Items { get; } = new ObservableCollection<QuarantineItem>();

        public QuarantineView()
        {
            InitializeComponent();
            DataContext = this;
            Loaded += (s, e) =>
            {
                PathText.Text = "保管場所: " + AppState.Quarantine.QuarantineDir;
                Reload();
            };
        }

        private void Reload()
        {
            Items.Clear();
            foreach (var i in AppState.Quarantine.LoadAll()) Items.Add(i);
        }

        private void Refresh_Click(object sender, RoutedEventArgs e) { Reload(); }

        private void Restore_Click(object sender, RoutedEventArgs e)
        {
            var sel = Grid1.SelectedItems.Cast<QuarantineItem>().ToList();
            if (sel.Count == 0) { MessageBox.Show("項目を選んでください。", "Aegis"); return; }

            if (MessageBox.Show(sel.Count + " 件を元の場所に戻します。\n" +
                    "検出は誤りだったと確認できている場合のみ実行してください。\n\n続行しますか？",
                    "Aegis", MessageBoxButton.OKCancel, MessageBoxImage.Warning) != MessageBoxResult.OK) return;

            int ok = 0;
            foreach (var item in sel)
            {
                try { AppState.Quarantine.Restore(item); ok++; }
                catch (Exception ex) { MessageBox.Show(item.FileName + " の復元に失敗しました。\n" + ex.Message, "Aegis"); }
            }
            Reload();
            MessageBox.Show(ok + " 件を復元しました。", "Aegis");
        }

        private void RestoreAs_Click(object sender, RoutedEventArgs e)
        {
            var item = Grid1.SelectedItem as QuarantineItem;
            if (item == null) return;

            var dlg = new SaveFileDialog
            {
                Title = "取り出し先を指定してください",
                FileName = item.FileName,
                Filter = "すべてのファイル (*.*)|*.*"
            };
            if (dlg.ShowDialog() != true) return;

            try
            {
                AppState.Quarantine.Restore(item, dlg.FileName);
                Reload();
                MessageBox.Show("取り出しました。", "Aegis");
            }
            catch (Exception ex)
            {
                MessageBox.Show("取り出しに失敗しました。\n" + ex.Message, "Aegis");
            }
        }

        private void Delete_Click(object sender, RoutedEventArgs e)
        {
            var sel = Grid1.SelectedItems.Cast<QuarantineItem>().ToList();
            if (sel.Count == 0) { MessageBox.Show("項目を選んでください。", "Aegis"); return; }

            if (MessageBox.Show(sel.Count + " 件を完全に削除します。元に戻せません。\n\n続行しますか？",
                    "Aegis", MessageBoxButton.OKCancel, MessageBoxImage.Warning) != MessageBoxResult.OK) return;

            foreach (var item in sel) AppState.Quarantine.DeletePermanently(item);
            Reload();
        }

        private void OpenFolder_Click(object sender, RoutedEventArgs e)
        {
            string dir = AppState.Quarantine.QuarantineDir;
            if (Directory.Exists(dir)) AppState.OpenPath(dir);
        }
    }
}
