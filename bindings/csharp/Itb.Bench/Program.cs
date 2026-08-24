// Bench entry point: `message` runs the Single Message shape,
// `stream` the stream-pump shape, `all` (default) both.

namespace Itb.Bench;

internal static class Program
{
    private static int Main(string[] args)
    {
        // Bench-scale allocation churn leaks Go scratch heap
        // unboundedly without a soft memory cap + aggressive GC; the
        // return values report the previous settings, not an error.
        Itb.Runtime.SetMemoryLimit(512L * 1024 * 1024);
        Itb.Runtime.SetGCPercent(20);

        switch (args.Length > 0 ? args[0] : "all")
        {
            case "message":
                BenchMessage.Run();
                return 0;
            case "stream":
                BenchStream.Run();
                return 0;
            case "all":
                BenchMessage.Run();
                BenchStream.Run();
                return 0;
            default:
                Console.Error.WriteLine("usage: Itb.Bench [message|stream|all]");
                return 2;
        }
    }
}
