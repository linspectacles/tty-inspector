# TTY Inspector

**Expose. Explore. Explain.**

TTY Inspector is a read-only Linux TTY/PTY subsystem inspector for terminal devices, pseudo-terminals, registered TTY drivers and line disciplines, and visible process-to-terminal relationships.

Current release: **0.0.6**

Repository: <https://github.com/linspectacles/tty-inspector>

<p align="center">
  <a href="https://github.com/brunonlinespace/brunonlinespace/blob/main/linspectacles/tty-inspector.png">
    <img
      src="https://raw.githubusercontent.com/brunonlinespace/brunonlinespace/main/linspectacles/tty-inspector.png"
      alt="TTY Inspector screenshot"
      width="900"
    >
  </a>
</p>

## What TTY Inspector is

TTY Inspector answers a focused question: **what terminal infrastructure does the running Linux kernel expose, and which visible processes are associated with those terminal endpoints?**

It separates terminal-device inventory, pseudo-terminal inventory, registered TTY drivers, registered line disciplines, and process controlling-terminal relationships instead of treating them as one undifferentiated list.

The applet does not open terminals for interactive I/O and does not elevate privileges.

## Highlights

- Five views: **TTY Devices**, **PTYs**, **Drivers**, **Line Disciplines**, and **Processes**.
- TTY device identity, device numbers, backing relationships and active-console attributes from sysfs.
- Pseudo-terminal inventory from `/dev/ptmx` and `/dev/pts/`.
- Registered TTY driver inventory from `/proc/tty/drivers`.
- Registered line disciplines from `/proc/tty/ldiscs`.
- Visible process controlling-terminal, session, process-group and state information from procfs.
- Explicit accounting for inaccessible and vanished processes during acquisition.
- Unrecognised nonblank registry lines are counted as unparsed records rather than turned into invented entries.
- Search, view-specific filtering, sortable inventory, Metadata Details, export, and persistent presentation settings.

## Data sources and acquisition

- `/proc/tty/drivers`
- `/proc/tty/ldiscs`
- `/sys/class/tty/`
- `/dev/tty*`
- `/dev/ptmx`
- `/dev/pts/`
- `/proc/<pid>/stat`
- `/proc/<pid>/status`

TTY Inspector treats process churn as normal acquisition behaviour. Processes that disappear during a scan are counted as vanished rather than treated as an application failure.

`/proc/tty/ldiscs` is registry state; it does not prove that a line discipline is attached to a particular terminal.

Numeric `/dev/pts` nodes are reported as devpts slave devices. The applet does not invent per-PTY master/slave pairings.

## Interface

The **View** selector provides **TTY Devices**, **PTYs**, **Drivers**, **Line Disciplines**, and **Processes**.

View-specific selectors include Type, Role, and TTY filters where meaningful. Filtering operates on acquired records. Metadata Details reports the selected record's identity, source and terminal/process context.

The **Options...** surface provides the normal LinSpectacles Appearance, Sources, Export and About treatment.

## Read-only and scope boundaries

TTY Inspector never writes to a TTY, allocates/destroys PTYs, changes terminal configuration or line disciplines, attaches/detaches controlling terminals, sends process signals, or captures shell input/history.

Process counts represent visible processes whose **controlling-terminal device number** matches the endpoint; they are not a count of every process that may have the device open as a file descriptor.

Login/session/seat semantics remain the responsibility of **Login Inspector**.

## Useful keyboard shortcuts

| Command | Shortcut |
| --- | --- |
| Toggle Metadata Details | `F3` |
| Toggle Metadata Details layout | `Ctrl+L` |
| Refresh active view | `Shift+F5` |
| Options | `Ctrl+/` |

## Running from source

The supplied source is directly runnable on Linux. The Python-side requirements are Python 3 and PyQt6.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install PyQt6
python3 -m linspectacles_tty_inspector.standalone
```

No RPM installation instructions are included in this README.

## LinSpectacles Hub

This applet can run independently, but it can also be installed and used inside **[LinSpectacles Hub](https://github.com/linspectacles/linspectacles-hub)**.

LinSpectacles Hub is the optional workbench for the LinSpectacles applet family. It provides shared applet discovery, navigation and management while each inspector remains independently runnable.

To install a portable or user applet through the Hub, open **Configuration... → Applets** and add the applet ZIP. Once discovered, the applet can be enabled and opened from the Hub navigation.

System-installed applets are discovered by the Hub from its system applet store and remain managed by the system package manager.

## Source layout and LinSpectacles integration

```text
linspectacles_tty_inspector/
├── __init__.py
├── standalone.py
├── LICENSE
├── applet.json
├── README.md
└── tty_inspector/
    ├── __init__.py
    ├── applet.py
    ├── _support.py
    └── icon.png
```

`applet.json` supplies the LinSpectacles identity and entrypoint metadata.

## Configuration

TTY Inspector persists only implemented presentation state. Those settings do not alter terminal devices or process state.

## Scope

TTY Inspector owns **TTY/PTY subsystem and visible process-to-terminal evidence**. **Login Inspector** remains authoritative for login sessions/users/seats, and broader hardware relationships remain with **Hardware Topology**.

## License

GNU General Public License v3.0 or later. See [`LICENSE`](LICENSE).

## Links

- LinSpectacles organisation: <https://github.com/linspectacles/>
- LinSpectacles Hub: <https://github.com/linspectacles/linspectacles-hub>
- Repository: <https://github.com/linspectacles/tty-inspector>
- Issues: <https://github.com/linspectacles/tty-inspector/issues>

<p align="center">
  <a href="https://github.com/linspectacles/tty-inspector">
    <img
      src="tty_inspector/icon.png"
      alt="TTY Inspector"
      width="256"
    >
  </a>
</p>
