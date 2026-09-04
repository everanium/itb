// eitb — command-line demonstrator for the ITB F# binding.
//
// Subcommands:
//
//   eitb version                                   library + binding versions
//   eitb profiles                                  registered profile catalogue
//   eitb encrypt <profile> <in-file> <out-file>    Single Message encrypt
//   eitb decrypt <profile> <blob-hex> <in-file> <out-file>
//
// `encrypt` prints the session blob to stderr as hex; feed that hex
// back to `decrypt` on the receiving side. `profiles` lists the
// registered profile catalogue one name per line; the profiles that
// carry a cipher surface are the ones `encrypt` / `decrypt` accept.

module EveraniumItb.FSharp.Eitb.Program

open System
open System.IO
open EveraniumItb.FSharp

let private cmdVersion () : int =
    printfn "libitb %s" (Runtime.version ())
    printfn "itb-fsharp %s" Runtime.BindingVersion
    0

// Prints the registered profile catalogue one name per line in the
// sorted order Pipeline.profiles returns.
let private cmdProfiles () : int =
    Pipeline.profiles () |> ItbError.get |> List.iter (printfn "%s")
    0

// Profiles whose canonical name begins with "streaming-" route
// through the one-shot streaming buffered pair instead of the Single
// Message pair.
let private isStreamingProfile (profile: string) : bool =
    profile.StartsWith("streaming-", StringComparison.Ordinal)

// Recursively create the parent directory of `path` (mkdir -p).
let private ensureParentDir (path: string) : unit =
    let parent = Path.GetDirectoryName(path)

    if not (String.IsNullOrEmpty parent) then
        Directory.CreateDirectory(parent) |> ignore

let private cmdEncrypt (profile: string) (inFile: string) (outFile: string) : int =
    let plain = File.ReadAllBytes inFile

    ItbError.get (
        itb {
            use! pipe = Pipeline.init profile Opts.empty

            let! wire =
                if isStreamingProfile profile then
                    Pipeline.encryptStreamOneShot pipe plain
                else
                    Pipeline.encryptMessage pipe plain

            ensureParentDir outFile
            File.WriteAllBytes(outFile, wire)
            let! blob = Pipeline.save pipe
            eprintfn "%s" (Convert.ToHexStringLower blob)
            printfn "encrypted %s -> %s (%d -> %d bytes)" inFile outFile plain.Length wire.Length
        }
    )

    0

let private cmdDecrypt (profile: string) (blobHex: string) (inFile: string) (outFile: string) : int =
    let blob = Convert.FromHexString blobHex
    let wire = File.ReadAllBytes inFile

    ItbError.get (
        itb {
            use! pipe = Pipeline.load blob

            let! plain =
                if isStreamingProfile profile then
                    Pipeline.decryptStreamOneShot pipe wire
                else
                    Pipeline.decryptMessage pipe wire

            ensureParentDir outFile
            File.WriteAllBytes(outFile, plain)
            printfn "decrypted %s -> %s (%d -> %d bytes)" inFile outFile wire.Length plain.Length
        }
    )

    0

[<EntryPoint>]
let main args =
    Runtime.setMemoryLimit (512L * 1024L * 1024L) |> ignore
    Runtime.setGCPercent 20 |> ignore

    try
        match List.ofArray args with
        | [ "version" ] -> cmdVersion ()
        | [ "profiles" ] -> cmdProfiles ()
        | [ "encrypt"; profile; inFile; outFile ] -> cmdEncrypt profile inFile outFile
        | [ "decrypt"; profile; blobHex; inFile; outFile ] -> cmdDecrypt profile blobHex inFile outFile
        | _ ->
            eprintfn "usage: eitb version"
            eprintfn "       eitb profiles"
            eprintfn "       eitb encrypt <profile> <in-file> <out-file>"
            eprintfn "       eitb decrypt <profile> <blob-hex> <in-file> <out-file>"
            2
    with e ->
        eprintfn "eitb: %s" e.Message
        1
