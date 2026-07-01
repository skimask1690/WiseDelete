# WiseDelfile Driver Wrapper

A lightweight Windows utility that loads the **WiseDelfile64.sys** kernel driver, performs the required device handshake, and issues IOCTL requests to delete files that cannot be removed through standard Windows APIs.

This project demonstrates how **CVE-2025-66680**, can be used to invoke the driver's file deletion functionality from user mode after loading the driver.

## Features

* Loads and unloads `WiseDelfile64.sys` at runtime.
* Performs the required driver handshake automatically.
* Sends the driver's delete IOCTL to remove files.
* Supports recursive directory deletion with the `-folder` flag.
* Cleans up the temporary driver service after execution.
* No C runtime dependency.

## Usage

```text
WiseDelete.exe <full_path> [-folder]
```

### Delete a File

```text
WiseDelete.exe "C:\Path\locked.file"
```

### Delete a Directory

```text
WiseDelete.exe "C:\Path\Folder" -folder
```

### Delete multiple files

```text
WiseDelete.exe "C:\Path\locked.file,C:\Path\locked2.file"
```

## Requirements

* Administrator privileges
* `WiseDelfile64.sys` located in the same directory as the executable

## ⚠️ Disclaimer

This tool is provided for educational and research purposes only. The author is not responsible for any misuse.

## License

This project is released under the [MIT License](LICENSE).
