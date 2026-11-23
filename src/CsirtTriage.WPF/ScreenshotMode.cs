using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using CsirtTriage.WPF.ViewModels;

namespace CsirtTriage.WPF;

/// <summary>
/// README screenshots: CsirtTriage.exe --screenshots &lt;case folder&gt; &lt;output folder&gt;
/// Opens the window on the case, goes through the panels (and runs the
/// collections that are ticked, so the run log, findings and case report have
/// data) and saves each panel as a PNG. Renders the window itself, so it does
/// not need a visible desktop. Used by the screenshots workflow.
/// </summary>
internal static class ScreenshotMode
{
    public static async Task<int> RunAsync(string caseFolder, string outDir)
    {
        Directory.CreateDirectory(outDir);
        var window = new MainWindow { Width = 1280, Height = 820, ShowActivated = false, WindowStartupLocation = WindowStartupLocation.Manual, Left = 0, Top = 0 };
        window.Show();
        var vm = (MainViewModel)window.DataContext;

        vm.CaseName = "INC-4711 web01 compromise";
        vm.Analyst = "Analyst";
        vm.CaseFolder = caseFolder;
        await Until(() => !vm.IsScanning && vm.Collections.Count > 0, TimeSpan.FromSeconds(60));

        await Shot(window, vm, "Case", Path.Combine(outDir, "case.png"));
        await Shot(window, vm, "Sources", Path.Combine(outDir, "sources.png"));
        await Shot(window, vm, "Settings", Path.Combine(outDir, "settings.png"));
        await Shot(window, vm, "Iocs", Path.Combine(outDir, "iocs.png"));

        // Run what is ticked, as an analyst would, then show the results
        await Navigate(window, vm, "Case");
        vm.RunCommand.Execute(null);
        await Until(() => vm.IsRunning, TimeSpan.FromSeconds(10));
        await Until(() => !vm.IsRunning && !vm.IsScanning, TimeSpan.FromMinutes(10));
        await Shot(window, vm, "Case", Path.Combine(outDir, "case-after-run.png"));
        await Shot(window, vm, "Run", Path.Combine(outDir, "run-log.png"));
        await Shot(window, vm, "Findings", Path.Combine(outDir, "findings.png"));
        await Shot(window, vm, "Report", Path.Combine(outDir, "case-report.png"));

        window.Close();
        return 0;
    }

    private static async Task Until(Func<bool> condition, TimeSpan timeout)
    {
        var end = DateTime.UtcNow + timeout;
        while (!condition())
        {
            if (DateTime.UtcNow > end) throw new TimeoutException("Screenshot mode: the window did not reach the expected state.");
            await Task.Delay(200);
        }
    }

    private static async Task Navigate(Window window, MainViewModel vm, string panel)
    {
        // Tick the matching navigation button too, so the sidebar shows the right panel
        foreach (var rb in Descendants<RadioButton>(window))
            if (rb.CommandParameter as string == panel) rb.IsChecked = true;
        vm.NavigateCommand.Execute(panel);
        await Settle();
    }

    private static async Task Shot(Window window, MainViewModel vm, string panel, string path)
    {
        await Navigate(window, vm, panel);
        await Task.Delay(500);   // timers (log flush) and bindings
        await Settle();

        var root = (FrameworkElement)window.Content;
        root.UpdateLayout();
        const double scale = 1.5;   // sharper in the README
        var bmp = new RenderTargetBitmap((int)(root.ActualWidth * scale), (int)(root.ActualHeight * scale), 96 * scale, 96 * scale, PixelFormats.Pbgra32);
        var white = new DrawingVisual();
        using (var dc = white.RenderOpen()) dc.DrawRectangle(Brushes.White, null, new Rect(0, 0, root.ActualWidth, root.ActualHeight));
        bmp.Render(white);
        bmp.Render(root);
        var png = new PngBitmapEncoder();
        png.Frames.Add(BitmapFrame.Create(bmp));
        using var fs = File.Create(path);
        png.Save(fs);
        Console.WriteLine($"Saved {path}");
    }

    private static Task Settle() =>
        Dispatcher.CurrentDispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle).Task;

    private static IEnumerable<T> Descendants<T>(DependencyObject root) where T : DependencyObject
    {
        for (int i = 0; i < VisualTreeHelper.GetChildrenCount(root); i++)
        {
            var child = VisualTreeHelper.GetChild(root, i);
            if (child is T t) yield return t;
            foreach (var d in Descendants<T>(child)) yield return d;
        }
    }
}
