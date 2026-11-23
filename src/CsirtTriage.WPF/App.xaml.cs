using System.Runtime.InteropServices;
using System.Windows;
using CsirtTriage.Core;
using Application = System.Windows.Application;

namespace CsirtTriage.WPF;

/// <summary>
/// Normal start opens the UI. With --case (or --help) it runs headless, the
/// same as the csirttriage CLI; see <see cref="Headless"/> for the options:
///   CsirtTriage.exe --case &lt;folder&gt; [--parallel n] [--only a,b] [--list] …
/// </summary>
public partial class App : Application
{
    [DllImport("kernel32.dll")] private static extern bool AttachConsole(int pid);

    protected override void OnStartup(StartupEventArgs e)
    {
        int shots = Array.FindIndex(e.Args, a => a.Equals("--screenshots", StringComparison.OrdinalIgnoreCase));
        if (shots >= 0 && shots + 2 < e.Args.Length)
        {
            AttachConsole(-1);
            ShutdownMode = ShutdownMode.OnExplicitShutdown;
            Dispatcher.InvokeAsync(async () =>
            {
                int code;
                try { code = await ScreenshotMode.RunAsync(Path.GetFullPath(e.Args[shots + 1]), Path.GetFullPath(e.Args[shots + 2])); }
                catch (Exception ex) { Console.Error.WriteLine($"[ERROR] {ex}"); code = 1; }
                Shutdown(code);
            });
            return;
        }

        bool headless = e.Args.Any(a => a.Equals("--case", StringComparison.OrdinalIgnoreCase)
                                     || a.Equals("--help", StringComparison.OrdinalIgnoreCase));
        if (!headless)
        {
            base.OnStartup(e);
            new MainWindow().Show();
            return;
        }

        AttachConsole(-1);
        Console.OutputEncoding = System.Text.Encoding.UTF8;
        // Off the UI thread: the headless run must not capture the dispatcher's context
        int code = Task.Run(() => Headless.RunAsync(e.Args, Console.Out, Console.Error)).GetAwaiter().GetResult();
        Shutdown(code);
    }
}
