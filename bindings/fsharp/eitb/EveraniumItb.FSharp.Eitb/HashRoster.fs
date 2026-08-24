// Hash-registry roster for the eitb `hashes` diagnostic.
//
// The C# binding's hash-registry iteration surface is internal
// (InternalsVisibleTo covers its own test / eitb assemblies only),
// so this diagnostic carries its own P/Invoke triple —
// ITB_HashCount / ITB_HashName / ITB_HashWidth — plus a resolver
// replicating the C# NativeLoader lookup order:
//
//   1. `ITB_LIBITB_PATH` environment variable (path to the shared
//      library file).
//   2. `<repo>/dist/<os>-<arch>/libitb.<ext>` located by walking up
//      from the executable directory (in-repo builds).
//   3. The OS default loader path.
//
// The binding library itself deliberately exposes no primitive
// enumeration; this surface exists only for the shell diagnostic.

module EveraniumItb.FSharp.Eitb.HashRoster

open System
open System.IO
open System.Runtime.InteropServices
open System.Text

[<Literal>]
let private LibName = "libitb"

[<DllImport(LibName)>]
extern int ITB_HashCount()

[<DllImport(LibName)>]
extern int ITB_HashName(int i, byte[] out_, unativeint capBytes, unativeint& outLen)

[<DllImport(LibName)>]
extern int ITB_HashWidth(int i)

let private libFilename =
    if RuntimeInformation.IsOSPlatform OSPlatform.Windows then "libitb.dll"
    elif RuntimeInformation.IsOSPlatform OSPlatform.OSX then "libitb.dylib"
    else "libitb.so"

let private platformLibDir =
    let os =
        if RuntimeInformation.IsOSPlatform OSPlatform.OSX then "darwin"
        elif RuntimeInformation.IsOSPlatform OSPlatform.Windows then "windows"
        else "linux"

    let arch =
        match RuntimeInformation.ProcessArchitecture with
        | Architecture.Arm64 -> "arm64"
        | _ -> "amd64"

    $"{os}-{arch}"

let private resolveDistPath () : string option =
    let rec walk (dir: DirectoryInfo) =
        if isNull dir then
            None
        else
            let candidate = Path.Combine(dir.FullName, "dist", platformLibDir, libFilename)
            if File.Exists candidate then Some candidate else walk dir.Parent

    walk (DirectoryInfo AppContext.BaseDirectory)

let private resolve (libraryName: string) (assembly: Reflection.Assembly) (searchPath: Nullable<DllImportSearchPath>) : nativeint =
    if libraryName <> LibName then
        IntPtr.Zero
    else
        match Environment.GetEnvironmentVariable "ITB_LIBITB_PATH" with
        | path when not (String.IsNullOrEmpty path) && File.Exists path -> NativeLibrary.Load path
        | _ ->
            match resolveDistPath () with
            | Some dist -> NativeLibrary.Load dist
            | None -> NativeLibrary.Load(libFilename, assembly, searchPath)

/// Registers the resolver for this assembly's P/Invoke stubs.
/// Invoked once before the first roster call.
let private registered =
    lazy (NativeLibrary.SetDllImportResolver(Reflection.Assembly.GetExecutingAssembly(), DllImportResolver resolve))

let private hashName (i: int) : string =
    let mutable need = 0un
    let rc = ITB_HashName(i, null, 0un, &need)

    if (rc <> 0 && rc <> 5) || need <= 1un then
        ""
    else
        let buf = Array.zeroCreate (int need)
        let rc = ITB_HashName(i, buf, unativeint buf.Length, &need)

        if rc <> 0 then
            ""
        else
            let len = if need > 0un then int need - 1 else 0
            Encoding.UTF8.GetString(buf, 0, len)

/// Prints the shipped hash primitive roster, one row per registry
/// entry: index, name, width.
let print () : unit =
    registered.Force() |> ignore
    let count = ITB_HashCount()

    for i in 0 .. count - 1 do
        printfn "%2d  %-12s %d bits" i (hashName i) (ITB_HashWidth i)
