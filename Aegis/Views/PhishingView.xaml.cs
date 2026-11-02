using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Aegis.Models;
using Aegis.Services;

namespace Aegis.Views
{
    public partial class PhishingView : UserControl
    {
        public ObservableCollection<UrlVerdict> Verdicts { get; } = new ObservableCollection<UrlVerdict>();
        public ObservableCollection<UrlSignal> Signals { get; } = new ObservableCollection<UrlSignal>();

        private readonly PhishingAnalyzer _analyzer = new PhishingAnalyzer();

        public PhishingView()
        {
            InitializeComponent();
            DataContext = this;
        }

        private void Analyze_Click(object sender, RoutedEventArgs e)
        {
            string text = InputBox.Text;
            if (string.IsNullOrWhiteSpace(text))
            {
                MessageBox.Show("URL かメール本文を入力してください。", "Aegis");
                return;
            }

            Verdicts.Clear();
            Signals.Clear();

            bool looksLikeSingleUrl = !text.Trim().Contains(" ") && !text.Contains("\n");

            if (looksLikeSingleUrl)
            {
                Verdicts.Add(_analyzer.AnalyzeUrl(text.Trim()));
            }
            else
            {
                var body = _analyzer.AnalyzeMailBody(text);
                if (body.Signals.Count > 0) Verdicts.Add(body);
                foreach (var v in _analyzer.AnalyzeText(text)) Verdicts.Add(v);

                if (Verdicts.Count == 0)
                {
                    // URLが見つからない場合も文面診断は載せる
                    Verdicts.Add(body);
                }
            }

            int worst = Verdicts.Count == 0 ? 0 : Verdicts.Max(v => v.Score);
            var top = Verdicts.OrderByDescending(v => v.Score).FirstOrDefault();

            VerdictBox.Visibility = Visibility.Visible;
            VerdictText.Text = "総合判定: " + (top != null ? top.Judgement : "判定できません") + "（" + worst + " 点）";
            VerdictText.Foreground = ToBrush(top != null ? top.JudgementColor : "#FF9AA5B5");
            VerdictSub.Text = BuildAdvice(worst);

            if (Verdicts.Count > 0) UrlGrid.SelectedIndex = 0;

            if (MainWindow.Instance != null)
                MainWindow.Instance.SetStatus("フィッシング判定: " + worst + " 点 / 対象 " + Verdicts.Count + " 件");
        }

        private static string BuildAdvice(int score)
        {
            if (score >= 75)
                return "リンクを開かず、メールごと削除してください。すでに情報を入力してしまった場合は、そのサービスのパスワードを変更し、カード会社や銀行へ連絡してください。";
            if (score >= 50)
                return "開かないでください。用件が本物か確認したい場合は、メールのリンクではなく、公式アプリやブックマークから自分でアクセスしてください。";
            if (score >= 25)
                return "不審な特徴があります。ID・パスワード・カード番号の入力は避け、送信元を別の手段で確認してください。";
            if (score >= 10)
                return "決定的ではありませんが、気になる点があります。入力を求められる情報の内容を確認してください。";
            return "機械的な危険信号は見つかりませんでした。ただし安全の保証ではありません。心当たりのないメールのリンクは開かないでください。";
        }

        private void UrlGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            Signals.Clear();
            var v = UrlGrid.SelectedItem as UrlVerdict;
            if (v == null) return;
            foreach (var s in v.Signals.OrderByDescending(x => x.Score)) Signals.Add(s);
        }

        private void Paste_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (Clipboard.ContainsText()) InputBox.Text = Clipboard.GetText();
            }
            catch (Exception ex)
            {
                AppLog.Warn("クリップボード取得に失敗: " + ex.Message);
            }
        }

        private void Clear_Click(object sender, RoutedEventArgs e)
        {
            InputBox.Clear();
            Verdicts.Clear();
            Signals.Clear();
            VerdictBox.Visibility = Visibility.Collapsed;
        }

        private void Help_Click(object sender, RoutedEventArgs e)
        {
            MessageBox.Show(
                "点数の目安\n" +
                "　0〜9 点 … 目立った危険信号なし\n" +
                "　10〜24 点 … 軽微な注意点あり\n" +
                "　25〜49 点 … 要注意\n" +
                "　50〜74 点 … 危険。開かないでください\n" +
                "　75 点以上 … フィッシングの疑いが濃厚\n\n" +
                "この判定はドメインの作り方や文面の特徴から機械的に推定したものです。\n" +
                "点数が低くても安全とは限りません。最終的には次の点で確認してください。\n\n" +
                "・そのメールを自分が待っていたか\n" +
                "・リンク先ではなく、公式アプリやブックマークから同じ内容を確認できるか\n" +
                "・パスワードやカード番号をメール経由で求められていないか",
                "判定の見方", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private static Brush ToBrush(string hex)
        {
            try { return (Brush)new BrushConverter().ConvertFromString(hex); }
            catch { return Brushes.White; }
        }
    }
}
