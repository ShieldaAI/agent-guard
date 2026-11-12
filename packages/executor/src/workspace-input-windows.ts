import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { userInfo } from 'node:os';
import { win32 } from 'node:path';
import { ExecutorError } from './store.js';

// Win32 path inspection followed by a pathname open cannot fence junction or rename
// races. Open every component by its parent's HANDLE, retain the entire chain and
// withhold delete/write sharing until the bounded copy and its final checks finish.
// NtOpenFile's RootDirectory and FILE_OPEN_REPARSE_POINT are documented by Microsoft:
// https://learn.microsoft.com/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntopenfile
const program = String.raw`
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try {
[Console]::OpenStandardOutput().WriteByte(0x41)
Microsoft.PowerShell.Utility\Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

public static class GuardWorkspaceInput {
    const uint ShareRead = 1, Synchronize = 0x100000, ReadAttributes = 0x80;
    const uint ReparseAttribute = 0x400, DirectoryAttribute = 0x10;
    const uint OpenReparsePoint = 0x200000, SynchronousIo = 0x20;
    const ushort MagicSuffix = 0x3144;

    [StructLayout(LayoutKind.Sequential)] struct UnicodeName {
        public ushort Length, MaximumLength;
        public IntPtr Buffer;
    }
    [StructLayout(LayoutKind.Sequential)] struct Attributes {
        public int Length;
        public IntPtr RootDirectory, ObjectName;
        public uint Flags;
        public IntPtr SecurityDescriptor, SecurityQualityOfService;
    }
    [StructLayout(LayoutKind.Sequential)] struct IoStatus { public IntPtr Status, Information; }
    [StructLayout(LayoutKind.Sequential)] struct FileInfo {
        public uint Attributes, CreatedLow, CreatedHigh, AccessLow, AccessHigh, WriteLow, WriteHigh;
        public uint Volume, SizeHigh, SizeLow, Links, FileHigh, FileLow;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr sa,
        uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", ExactSpelling = true)]
    static extern bool GetFileInformationByHandle(SafeFileHandle file, out FileInfo info);
    [DllImport("kernel32.dll", ExactSpelling = true)]
    static extern uint GetFileType(SafeFileHandle file);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    static extern uint GetFinalPathNameByHandleW(SafeFileHandle file, StringBuilder path, uint capacity, uint flags);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    static extern uint GetDriveTypeW(string root);
    [DllImport("ntdll.dll", ExactSpelling = true)]
    static extern int NtOpenFile(out SafeFileHandle file, uint access, ref Attributes attributes,
        out IoStatus status, uint share, uint options);

    static void Ensure(bool condition) {
        if (!condition) throw new InvalidDataException();
    }

    static SafeFileHandle OpenChild(SafeFileHandle parent, string component, bool directory) {
        IntPtr text = Marshal.StringToHGlobalUni(component);
        IntPtr name = IntPtr.Zero;
        try {
            name = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UnicodeName)));
            ushort length = checked((ushort)(component.Length * 2));
            Marshal.StructureToPtr(new UnicodeName { Length = length, MaximumLength = length, Buffer = text }, name, false);
            var attributes = new Attributes { Length = Marshal.SizeOf(typeof(Attributes)),
                RootDirectory = parent.DangerousGetHandle(), ObjectName = name,
                Flags = 0x40 | 0x1000 }; // OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE
            SafeFileHandle file;
            IoStatus status;
            uint access = ReadAttributes | Synchronize | (directory ? 0x20U : 1U); // traverse / read data
            uint options = OpenReparsePoint | SynchronousIo | (directory ? 1U : 0x40U); // directory / non-directory
            int result = NtOpenFile(out file, access, ref attributes, out status, ShareRead, options);
            if (result != 0 || file == null || file.IsInvalid) {
                if (file != null) file.Dispose();
                throw new IOException();
            }
            return file;
        } finally {
            if (name != IntPtr.Zero) Marshal.FreeHGlobal(name);
            Marshal.FreeHGlobal(text);
        }
    }

    static FileInfo Inspect(SafeFileHandle file, ref string expected, bool directory, string selectedComponent) {
        FileInfo info;
        Ensure(!file.IsInvalid && GetFileType(file) == 1); // FILE_TYPE_DISK
        Ensure(GetFileInformationByHandle(file, out info));
        Ensure((info.Attributes & ReparseAttribute) == 0 && ((info.Attributes & DirectoryAttribute) != 0) == directory);
        if (!directory) Ensure(info.Links == 1);
        var actual = new StringBuilder(32768);
        uint size = GetFinalPathNameByHandleW(file, actual, (uint)actual.Capacity, 0);
        Ensure(size != 0 && size < actual.Capacity);
        // Windows can supply a short-name ancestor in os.tmpdir(). Resolve that
        // workspace-root spelling from the handle we already opened and retained.
        // Its canonical name must still be a direct child of the pinned parent.
        // Selected relative components keep their exact spelling checks below.
        string normalized = actual.ToString();
        if (!String.Equals(normalized, expected, StringComparison.OrdinalIgnoreCase)) {
            Ensure(selectedComponent == null && directory && expected.Length > 7);
            int prefixLength = expected.LastIndexOf('\\') + 1;
            Ensure(normalized.Length > prefixLength &&
                normalized.StartsWith(expected.Substring(0, prefixLength), StringComparison.OrdinalIgnoreCase) &&
                normalized.IndexOf('\\', prefixLength) == -1);
        }
        expected = normalized;
        if (selectedComponent != null) Ensure(normalized.EndsWith("\\" + selectedComponent, StringComparison.Ordinal));
        return info;
    }

    static string ReadString(BinaryReader input, int maxChars) {
        int length = input.ReadInt32();
        Ensure(length > 0 && length <= maxChars * 2 && length % 2 == 0);
        byte[] bytes = input.ReadBytes(length);
        Ensure(bytes.Length == length);
        return new UnicodeEncoding(false, false, true).GetString(bytes);
    }

    public static void Run() {
        int limit;
        string root, name;
        using (var input = new BinaryReader(Console.OpenStandardInput())) {
            limit = input.ReadInt32();
            Ensure(limit >= 0 && limit <= 64 * 1024 * 1024);
            root = ReadString(input, 8192);
            name = ReadString(input, 1024);
            Ensure(input.BaseStream.ReadByte() == -1);
        }
        // The caller validates literal drive paths and components before encoding this request.
        string drive = Char.ToUpperInvariant(root[0]) + @":\";
        Ensure(GetDriveTypeW(drive) == 3); // local fixed volume
        string expected = @"\\?\" + drive;
        string[] rootParts = root.Substring(3).Split(new char[] { '\\' }, StringSplitOptions.RemoveEmptyEntries);
        string[] selected = name.Split('\\');
        var held = new List<SafeFileHandle>();
        try {
            var current = CreateFileW(expected, Synchronize | ReadAttributes | 0x20, ShareRead, IntPtr.Zero,
                3, 0x02000000 | OpenReparsePoint, IntPtr.Zero); // OPEN_EXISTING | BACKUP_SEMANTICS
            held.Add(current);
            Inspect(current, ref expected, true, null);
            for (int i = 0; i < rootParts.Length + selected.Length; i++) {
                bool workspacePart = i < rootParts.Length;
                string component = workspacePart ? rootParts[i] : selected[i - rootParts.Length];
                bool directory = i != rootParts.Length + selected.Length - 1;
                current = OpenChild(current, component, directory);
                held.Add(current);
                expected = expected.TrimEnd('\\') + "\\" + component;
                FileInfo before = Inspect(current, ref expected, directory, workspacePart ? null : component);
                if (directory) continue;
                Ensure(before.SizeHigh == 0 && before.SizeLow <= limit);
                var bytes = new byte[(int)before.SizeLow];
                using (var stream = new FileStream(current, FileAccess.Read)) {
                    int offset = 0;
                    while (offset < bytes.Length) {
                        int count = stream.Read(bytes, offset, bytes.Length - offset);
                        Ensure(count > 0);
                        offset += count;
                    }
                    Ensure(stream.ReadByte() == -1);
                    FileInfo after = Inspect(current, ref expected, false, component);
                    Ensure(after.SizeLow == before.SizeLow && after.SizeHigh == 0 &&
                        after.WriteLow == before.WriteLow && after.WriteHigh == before.WriteHigh);
                }
                using (var output = new BinaryWriter(Console.OpenStandardOutput())) {
                    output.Write(MagicSuffix); output.Write(bytes.Length); output.Write(bytes);
                }
            }
        } finally { for (int i = held.Count - 1; i >= 0; i--) held[i].Dispose(); }
    }
}
'@
[Console]::OpenStandardOutput().WriteByte(0x47)
[GuardWorkspaceInput]::Run()
exit 0
} catch { exit 1 }
`;

const encodedProgram = Buffer.from(program, 'utf16le').toString('base64');

type Failure = 'selection' | 'startup' | 'timeout' | 'spawn' | 'exit' | 'protocol' | 'cleanup';
type Stage = 'not-started' | 'compiling' | 'copying' | 'complete';

class WorkspaceInputError extends ExecutorError {
  constructor(
    readonly reason: Failure,
    readonly stage: Stage,
  ) {
    super('WORKSPACE_INPUT_UNAVAILABLE', { detail: reason.toUpperCase() });
    this.message = `Workspace input unavailable or unsafe: symlinks, reparse points, hard links and oversized files are refused (${reason}; ${stage})`;
  }
}

function deny(reason: Failure = 'selection', stage: Stage = 'not-started'): never {
  throw new WorkspaceInputError(reason, stage);
}

function helperStage(stdout: Buffer | null | undefined): Stage {
  // The first two bytes of the existing magic header also mark startup stages.
  // Keep the successful frame and aggregate maxBuffer unchanged. Never expose
  // compiler output, native errors, selected paths, or stderr to the caller.
  if (!stdout || stdout[0] !== 0x41) return 'not-started';
  if (stdout[1] !== 0x47) return 'compiling';
  return stdout.length >= 8 && stdout.readUInt32LE(0) === 0x31444741 ? 'complete' : 'copying';
}

function validComponent(part: string): boolean {
  return (
    part.length > 0 &&
    part.length <= 255 &&
    part !== '.' &&
    part !== '..' &&
    part.normalize('NFC') === part &&
    !/[\u0000-\u001f\u007f<>:"|?*]/u.test(part) &&
    !/[. ]$/u.test(part) &&
    !/^(?:con|prn|aux|nul|conin\$|conout\$|com[0-9¹²³]|lpt[0-9¹²³])(?:\.|$)/iu.test(part)
  );
}

/** Copy one regular file through retained Windows handles. PowerShell and the OS installation are trusted host components. */
export function readWindowsWorkspaceInput(root: string, name: string, maximum: number): Buffer {
  if (
    process.platform !== 'win32' ||
    typeof root !== 'string' ||
    typeof name !== 'string' ||
    !Number.isSafeInteger(maximum) ||
    maximum < 0 ||
    maximum > 64 * 1024 * 1024
  )
    deny();
  root = root.replaceAll('/', '\\');
  name = name.replaceAll('/', '\\');
  if (!/^[a-z]:\\/iu.test(root) || root.length > 8192 || name.length > 1024) deny();
  if (root.length > 3 && root.endsWith('\\')) root = root.slice(0, -1);
  const parents = root.length === 3 ? [] : root.slice(3).split('\\');
  if (![...parents, ...name.split('\\')].every(validComponent)) deny();

  const systemRoot = process.env.SystemRoot;
  if (!systemRoot || !/^[a-z]:\\/iu.test(systemRoot) || win32.normalize(systemRoot) !== systemRoot) deny();
  const system = win32.join(systemRoot, 'System32');
  const shell = win32.join(system, 'WindowsPowerShell', 'v1.0');
  const fields = [root, name].map(value => Buffer.from(value, 'utf16le'));
  const chunks = [Buffer.alloc(4)];
  chunks[0]!.writeUInt32LE(maximum);
  for (const value of fields) {
    const length = Buffer.alloc(4);
    length.writeUInt32LE(value.length);
    chunks.push(length, value);
  }
  let scratch: string | undefined;
  let observedStage: Stage = 'not-started';
  try {
    // Add-Type may compile to disk. Use the OS account's private profile, never the workspace or caller's TEMP.
    scratch = mkdtempSync(win32.join(userInfo().homedir, 'AppData', 'Local', 'Temp', 'agent-guard-input-'));
    const child = spawnSync(
      win32.join(shell, 'powershell.exe'),
      ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', encodedProgram],
      {
        cwd: system,
        windowsHide: true,
        timeout: 30_000,
        maxBuffer: Math.max(4096, maximum + 8),
        input: Buffer.concat(chunks),
        // Load Windows' own PowerShell modules and compiler, independent of the caller's search path and profile.
        env: {
          SystemRoot: systemRoot,
          WINDIR: systemRoot,
          SystemDrive: systemRoot.slice(0, 2),
          PATH: system,
          ComSpec: win32.join(system, 'cmd.exe'),
          PSModulePath: win32.join(shell, 'Modules'),
          TEMP: scratch,
          TMP: scratch,
        },
      },
    );
    const data = child.stdout;
    const stage = (observedStage = helperStage(data));
    if (child.error) deny((child.error as NodeJS.ErrnoException).code === 'ETIMEDOUT' ? 'timeout' : 'spawn', stage);
    if (child.status !== 0) deny('exit', stage);
    if (
      !data ||
      data.length < 8 ||
      data.readUInt32LE(0) !== 0x31444741 ||
      data.readUInt32LE(4) > maximum ||
      data.length !== data.readUInt32LE(4) + 8
    )
      deny('protocol', stage);
    return data.subarray(8);
  } catch (error) {
    if (error instanceof WorkspaceInputError) throw error;
    return deny('startup');
  } finally {
    try {
      if (scratch) rmSync(scratch, { recursive: true, force: true });
    } catch {
      deny('cleanup', observedStage);
    }
  }
}
