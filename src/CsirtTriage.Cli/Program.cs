using CsirtTriage.Core;

// Headless runner; see CsirtTriage.Core.Headless for the options.
using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, a) => { a.Cancel = true; cts.Cancel(); };
return await Headless.RunAsync(args, Console.Out, Console.Error, cts.Token);
