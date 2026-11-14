#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# LinSpectacles - Linux Inspection Suite
# Copyright (C) 2026 brunonlinespace
# GPL-3.0-or-later

APPLET_ID = "linspectacles-tty-inspector"
APPLET_NAME = "TTY Inspector"
APPLET_VERSION = "0.0.5"
APPLET_AUTHOR = "brunonlinespace"
APPLET_EDITOR = "brunonlinespace"
APPLET_PUBLISHER = "brunonlinespace"
APPLET_REPOSITORY = "https://github.com/linspectacles/tty-inspector"

import os
import pwd
import re
import stat
from pathlib import Path

from PyQt6.QtCore import QSettings, Qt, QUrl
from PyQt6.QtGui import QColor, QKeySequence, QPixmap, QShortcut, QTextCharFormat, QTextCursor
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from ._support import (
    BaseInspectorTab,
    export_records_dialog,
    metadata_font_qss,
)


VIEW_TTY = "TTY Devices"
VIEW_PTY = "PTYs"
VIEW_DRIVERS = "Drivers"
VIEW_LDISCS = "Line Disciplines"
VIEW_PROCESSES = "Processes"
VIEWS = [VIEW_TTY, VIEW_PTY, VIEW_DRIVERS, VIEW_LDISCS, VIEW_PROCESSES]

VIEW_CONFIG = {
    VIEW_TTY: {
        "total": "Total TTY Devices",
        "columns": [
            ("tty", "TTY", 120, "left"),
            ("major_minor", "Major:Minor", 100, "left"),
            ("driver_type", "Driver / Type", 190, "left"),
            ("active", "Active", 75, "left"),
            ("console", "Console", 75, "left"),
            ("process_count", "Process Count", 105, "right"),
            ("device_path", "Device Path", 170, "left"),
        ],
        "numeric": {"process_count"},
        "selector_label": "Type:",
        "selector_all": "All Types",
        "selector_key": "type_filter",
    },
    VIEW_PTY: {
        "total": "Total PTYs",
        "columns": [
            ("pty", "PTY", 120, "left"),
            ("role", "Role", 150, "left"),
            ("major_minor", "Major:Minor", 100, "left"),
            ("visible_processes", "Visible Processes", 120, "right"),
            ("representative_pid", "Representative PID", 130, "right"),
            ("device_path", "Device Path", 190, "left"),
        ],
        "numeric": {"visible_processes", "representative_pid"},
        "selector_label": "Role:",
        "selector_all": "All Roles",
        "selector_key": "role",
    },
    VIEW_DRIVERS: {
        "total": "Total TTY Drivers",
        "columns": [
            ("driver", "Driver", 190, "left"),
            ("device_prefix", "Device Prefix", 170, "left"),
            ("major", "Major", 80, "right"),
            ("minor_range", "Minor Range", 120, "left"),
            ("type", "Type", 160, "left"),
        ],
        "numeric": {"major"},
        "selector_label": "Type:",
        "selector_all": "All Types",
        "selector_key": "type",
    },
    VIEW_LDISCS: {
        "total": "Total Line Disciplines",
        "columns": [
            ("line_discipline", "Line Discipline", 260, "left"),
            ("identifier", "Number / Identifier", 150, "right"),
        ],
        "numeric": {"identifier"},
        "selector_label": None,
        "selector_all": None,
        "selector_key": None,
    },
    VIEW_PROCESSES: {
        "total": "Visible Processes with TTY",
        "columns": [
            ("process", "Process", 180, "left"),
            ("pid", "PID", 85, "right"),
            ("uid_user", "UID / User", 150, "left"),
            ("tty", "TTY", 120, "left"),
            ("session_id", "Session ID", 100, "right"),
            ("process_group", "Process Group", 110, "right"),
            ("state", "State", 75, "left"),
        ],
        "numeric": {"pid", "session_id", "process_group"},
        "selector_label": "TTY:",
        "selector_all": "All TTYs",
        "selector_key": "tty",
    },
}


def _read_text(path):
    path = Path(path)
    try:
        return "observed", path.read_text(encoding="utf-8", errors="replace").strip()
    except PermissionError:
        return "restricted", ""
    except FileNotFoundError:
        return "unavailable", ""
    except OSError as exc:
        return "error", str(exc)


def _safe_resolve(path):
    try:
        return str(Path(path).resolve(strict=True))
    except (FileNotFoundError, PermissionError, OSError):
        return ""


def _device_number(path):
    try:
        info = os.stat(path)
    except (FileNotFoundError, PermissionError, OSError):
        return None
    if not stat.S_ISCHR(info.st_mode):
        return None
    try:
        return os.major(info.st_rdev), os.minor(info.st_rdev)
    except (TypeError, ValueError, OSError):
        return None


def _parse_major_minor(text):
    try:
        major_text, minor_text = str(text).strip().split(":", 1)
        return int(major_text), int(minor_text)
    except (ValueError, TypeError):
        return None


def _minor_in_range(minor, text):
    text = str(text or "").strip()
    try:
        if "-" in text:
            start, end = text.split("-", 1)
            return int(start) <= minor <= int(end)
        return minor == int(text)
    except ValueError:
        return False


def _parse_tty_drivers():
    path = Path("/proc/tty/drivers")
    rows = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except PermissionError:
        return [], "restricted", "", 0
    except FileNotFoundError:
        return [], "unavailable", "", 0
    except OSError as exc:
        return [], "error", str(exc), 0

    pattern = re.compile(r"^(.*?)\s+(/dev/\S+)\s+(\d+)\s+(\S+)\s+(\S+)\s*$")
    unparsed = 0
    for raw_line in lines:
        if not raw_line.strip():
            continue
        match = pattern.match(raw_line)
        if not match:
            # Count unknown nonblank kernel records; never invent their fields.
            unparsed += 1
            continue
        driver, device_prefix, major, minor_range, driver_type = match.groups()
        rows.append(
            {
                "driver": driver.strip(),
                "device_prefix": device_prefix,
                "major": int(major),
                "minor_range": minor_range,
                "type": driver_type,
                "_source_line": raw_line,
            }
        )
    rows.sort(key=lambda item: (str(item.get("driver", "")).lower(), item.get("major", 0)))
    return rows, "observed", "", unparsed


def _parse_line_disciplines():
    path = Path("/proc/tty/ldiscs")
    rows = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except PermissionError:
        return [], "restricted", "", 0
    except FileNotFoundError:
        return [], "unavailable", "", 0
    except OSError as exc:
        return [], "error", str(exc), 0

    pattern = re.compile(r"^\s*(.*?)\s+(\d+)\s*$")
    unparsed = 0
    for raw_line in lines:
        if not raw_line.strip():
            continue
        match = pattern.match(raw_line)
        if not match:
            unparsed += 1
            continue
        name, identifier = match.groups()
        rows.append(
            {
                "line_discipline": name.strip(),
                "identifier": int(identifier),
                "_source_line": raw_line,
            }
        )
    rows.sort(key=lambda item: (item.get("identifier", 0), str(item.get("line_discipline", "")).lower()))
    return rows, "observed", "", unparsed


def _decode_tty_nr(raw_tty_nr):
    try:
        value = int(raw_tty_nr)
    except (TypeError, ValueError):
        return None
    if value == 0:
        return None
    value &= 0xFFFFFFFF
    major = (value >> 8) & 0xFFF
    minor = (value & 0xFF) | ((value >> 12) & 0xFFF00)
    return major, minor


def _parse_proc_stat(text):
    text = str(text or "").strip()
    left = text.find("(")
    right = text.rfind(")")
    if left <= 0 or right <= left:
        raise ValueError("unrecognised /proc/<pid>/stat format")
    pid = int(text[:left].strip())
    comm = text[left + 1 : right]
    fields = text[right + 1 :].strip().split()
    if len(fields) < 5:
        raise ValueError("short /proc/<pid>/stat record")
    return {
        "pid": pid,
        "process": comm,
        "state": fields[0],
        "process_group": int(fields[2]),
        "session_id": int(fields[3]),
        "tty_nr": int(fields[4]),
    }


def _status_uid(text):
    for line in str(text or "").splitlines():
        if line.startswith("Uid:"):
            parts = line.split()
            if len(parts) >= 2:
                try:
                    return int(parts[1])
                except ValueError:
                    return None
    return None


def _user_for_uid(uid):
    if uid is None:
        return ""
    try:
        return pwd.getpwuid(uid).pw_name
    except (KeyError, OSError):
        return ""


def _driver_for_device(major, minor, tty_name, drivers):
    candidates = [
        item
        for item in drivers
        if item.get("major") == major and _minor_in_range(minor, item.get("minor_range"))
    ]
    if not candidates:
        return None

    device_path = f"/dev/{tty_name}"
    for item in candidates:
        prefix = str(item.get("device_prefix", ""))
        if device_path == prefix or device_path.startswith(prefix):
            return item
    return candidates[0]


def _console_names():
    names = set()
    raw_values = {}
    for path in (Path("/sys/class/tty/console/active"), Path("/sys/class/tty/tty0/active")):
        state, value = _read_text(path)
        raw_values[str(path)] = (state, value)
        if state == "observed":
            names.update(part for part in value.split() if part)
    return names, raw_values


def _collect_tty_devices(drivers):
    root = Path("/sys/class/tty")
    active_names, active_sources = _console_names()
    has_active_evidence = any(
        state == "observed" and bool(value.strip())
        for state, value in active_sources.values()
    )
    records = []
    try:
        entries = sorted(root.iterdir(), key=lambda item: item.name.lower())
    except PermissionError:
        return [], "restricted", ""
    except (FileNotFoundError, NotADirectoryError):
        return [], "unavailable", ""
    except OSError as exc:
        return [], "error", str(exc)

    for entry in entries:
        name = entry.name
        dev_state, dev_value = _read_text(entry / "dev")
        dev_number = _parse_major_minor(dev_value) if dev_state == "observed" else None
        major = dev_number[0] if dev_number else None
        minor = dev_number[1] if dev_number else None
        major_minor = f"{major}:{minor}" if dev_number else "Not reported"

        device_node = Path("/dev") / name
        device_path = str(device_node) if device_node.exists() else "Not present"

        proc_driver = _driver_for_device(major, minor, name, drivers) if dev_number else None
        sysfs_driver_path = entry / "device" / "driver"
        sysfs_driver = Path(_safe_resolve(sysfs_driver_path)).name if _safe_resolve(sysfs_driver_path) else ""
        proc_type = str(proc_driver.get("type", "")) if proc_driver else ""
        proc_name = str(proc_driver.get("driver", "")) if proc_driver else ""

        if sysfs_driver and proc_type:
            driver_type = f"{sysfs_driver} / {proc_type}"
        elif proc_name and proc_type:
            driver_type = f"{proc_name} / {proc_type}"
        elif sysfs_driver:
            driver_type = sysfs_driver
        elif proc_type:
            driver_type = proc_type
        else:
            driver_type = "Not reported"

        type_filter = proc_type or sysfs_driver or proc_name or "Not reported"
        console = bool((proc_type and "console" in proc_type.lower()) or name in active_names or name == "console")
        active = "Yes" if name in active_names else ("No" if has_active_evidence else "Unknown")

        backing_device = _safe_resolve(entry / "device")
        modalias_state, modalias = _read_text(entry / "device" / "modalias")
        uevent_state, uevent = _read_text(entry / "device" / "uevent")

        records.append(
            {
                "tty": name,
                "device_path": device_path,
                "major_minor": major_minor,
                "driver_type": driver_type,
                "active": active,
                "console": "Yes" if console else "No",
                "process_count": 0,
                "type_filter": type_filter,
                "_major": major,
                "_minor": minor,
                "_sysfs_path": str(entry),
                "_backing_device": backing_device,
                "_sysfs_driver": sysfs_driver,
                "_proc_driver": proc_name,
                "_proc_type": proc_type,
                "_modalias": modalias if modalias_state == "observed" else "",
                "_uevent": uevent if uevent_state == "observed" else "",
                "_active_sources": active_sources,
            }
        )
    return records, "observed", ""


def _checked_pty_number(path):
    """Read device identity by stat(2) only, preserving why it was unavailable."""
    try:
        info = os.stat(path)
    except PermissionError:
        return None, "restricted", ""
    except (FileNotFoundError, NotADirectoryError):
        return None, "unavailable", ""
    except OSError as exc:
        return None, "error", str(exc)
    if not stat.S_ISCHR(info.st_mode):
        return None, "error", "not a character device"
    return (os.major(info.st_rdev), os.minor(info.st_rdev)), "observed", ""


def _collect_ptys():
    records = []
    sources = {}
    node_failures = {"unavailable": 0, "restricted": 0, "error": 0}

    ptmx = Path("/dev/ptmx")
    ptmx_dev, ptmx_state, ptmx_error = _checked_pty_number(ptmx)
    sources[str(ptmx)] = (ptmx_state, ptmx_error)
    if ptmx_dev:
        records.append(
            {
                "pty": "ptmx",
                "role": "Master multiplexer",
                "device_path": str(ptmx),
                "major_minor": f"{ptmx_dev[0]}:{ptmx_dev[1]}",
                "visible_processes": 0,
                "representative_pid": "",
                "_major": ptmx_dev[0],
                "_minor": ptmx_dev[1],
                "_source": "/dev/ptmx",
            }
        )

    pts_root = Path("/dev/pts")
    try:
        entries = sorted(
            [item for item in pts_root.iterdir() if item.name.isdigit()],
            key=lambda item: int(item.name),
        )
    except PermissionError:
        sources[str(pts_root)] = ("restricted", "")
        entries = []
    except (FileNotFoundError, NotADirectoryError):
        sources[str(pts_root)] = ("unavailable", "")
        entries = []
    except OSError as exc:
        sources[str(pts_root)] = ("error", str(exc))
        entries = []
    else:
        sources[str(pts_root)] = ("observed", "")

    for item in entries:
        dev, state, _error = _checked_pty_number(item)
        if not dev:
            node_failures[state] += 1
            continue
        records.append(
            {
                "pty": f"pts/{item.name}",
                "role": "Slave device",
                "device_path": str(item),
                "major_minor": f"{dev[0]}:{dev[1]}",
                "visible_processes": 0,
                "representative_pid": "",
                "_major": dev[0],
                "_minor": dev[1],
                "_source": "/dev/pts/",
            }
        )
    return records, sources, node_failures


def _tty_display_map(tty_records, pty_records):
    mapping = {}
    for record in tty_records:
        if record.get("_major") is not None and record.get("_minor") is not None:
            mapping[(record["_major"], record["_minor"])] = record.get("tty", record.get("major_minor", ""))
    for record in pty_records:
        if record.get("_major") is not None and record.get("_minor") is not None:
            mapping[(record["_major"], record["_minor"])] = record.get("pty", record.get("major_minor", ""))
    return mapping


def _collect_processes(tty_records, pty_records):
    proc_root = Path("/proc")
    display_map = _tty_display_map(tty_records, pty_records)
    records = []
    inaccessible = 0
    vanished = 0
    errors = 0

    try:
        pid_dirs = sorted(
            [item for item in proc_root.iterdir() if item.name.isdigit()],
            key=lambda item: int(item.name),
        )
    except (PermissionError, OSError) as exc:
        return [], {"inaccessible": 0, "vanished": 0, "errors": 1, "error_text": str(exc)}

    for proc_dir in pid_dirs:
        pid = int(proc_dir.name)
        try:
            stat_text = (proc_dir / "stat").read_text(encoding="utf-8", errors="replace")
        except FileNotFoundError:
            vanished += 1
            continue
        except PermissionError:
            inaccessible += 1
            continue
        except OSError:
            errors += 1
            continue

        try:
            parsed = _parse_proc_stat(stat_text)
        except (ValueError, TypeError):
            errors += 1
            continue

        dev_number = _decode_tty_nr(parsed.get("tty_nr"))
        if not dev_number:
            continue

        uid = None
        status_access = "observed"
        try:
            status_text = (proc_dir / "status").read_text(encoding="utf-8", errors="replace")
            uid = _status_uid(status_text)
        except FileNotFoundError:
            vanished += 1
            continue
        except PermissionError:
            inaccessible += 1
            status_access = "restricted"
        except OSError:
            errors += 1
            status_access = "error"

        user = _user_for_uid(uid)
        if uid is None:
            uid_user = "Restricted" if status_access == "restricted" else "Not reported"
        elif user:
            uid_user = f"{uid} / {user}"
        else:
            uid_user = str(uid)

        tty_name = display_map.get(dev_number, f"{dev_number[0]}:{dev_number[1]}")
        records.append(
            {
                "process": parsed.get("process", ""),
                "pid": pid,
                "uid_user": uid_user,
                "tty": tty_name,
                "session_id": parsed.get("session_id", 0),
                "process_group": parsed.get("process_group", 0),
                "state": parsed.get("state", ""),
                "_uid": uid,
                "_tty_major": dev_number[0],
                "_tty_minor": dev_number[1],
                "_tty_nr_raw": parsed.get("tty_nr", 0),
                "_status_access": status_access,
            }
        )

    records.sort(key=lambda item: (str(item.get("tty", "")).lower(), item.get("pid", 0)))
    return records, {"inaccessible": inaccessible, "vanished": vanished, "errors": errors, "error_text": ""}


def _apply_process_counts(tty_records, pty_records, process_records):
    by_dev = {}
    pids_by_dev = {}
    for record in process_records:
        key = (record.get("_tty_major"), record.get("_tty_minor"))
        by_dev[key] = by_dev.get(key, 0) + 1
        pids_by_dev.setdefault(key, []).append(record.get("pid", 0))

    for record in tty_records:
        key = (record.get("_major"), record.get("_minor"))
        record["process_count"] = by_dev.get(key, 0)
    for record in pty_records:
        key = (record.get("_major"), record.get("_minor"))
        pids = sorted(pid for pid in pids_by_dev.get(key, []) if isinstance(pid, int))
        record["visible_processes"] = len(pids)
        record["representative_pid"] = pids[0] if pids else ""


class TTYInspectorOptionsDialog(QDialog):
    """Kernel Modules-authoritative Options treatment adapted only to TTY Inspector."""

    def __init__(self, owner):
        super().__init__(owner)
        self.owner = owner
        self.setWindowTitle("Options — TTY Inspector")
        self.resize(980, 720)

        root = QVBoxLayout(self)
        tabs = QTabWidget()
        root.addWidget(tabs, 1)

        appearance_page = QWidget()
        appearance_layout = QVBoxLayout(appearance_page)
        appearance_layout.setContentsMargins(12, 12, 12, 12)
        appearance_layout.setSpacing(10)

        appearance_heading = QLabel("Metadata display")
        heading_font = appearance_heading.font()
        heading_font.setBold(True)
        appearance_heading.setFont(heading_font)
        appearance_layout.addWidget(appearance_heading)

        appearance_note = QLabel(
            "Choose how the inventory and Metadata Details panes are arranged. "
            "This TTY Inspector setting is remembered."
        )
        appearance_note.setWordWrap(True)
        appearance_layout.addWidget(appearance_note)

        layout_row = QHBoxLayout()
        layout_row.addWidget(QLabel("Record details layout:"))
        self.layout_combo = QComboBox()
        self.layout_combo.addItems(["Horizontal", "Vertical"])
        self.layout_combo.setCurrentText(
            "Vertical" if owner.details_orientation == "vertical" else "Horizontal"
        )
        self.layout_combo.currentTextChanged.connect(self._layout_changed)
        layout_row.addWidget(self.layout_combo)
        layout_row.addStretch(1)
        appearance_layout.addLayout(layout_row)

        self.show_metadata_panel = QCheckBox("Show Metadata Details panel (F3)")
        self.show_metadata_panel.setChecked(owner.metadata_panel_visible)
        self.show_metadata_panel.toggled.connect(self._metadata_panel_changed)
        appearance_layout.addWidget(self.show_metadata_panel)

        shortcut_note = QLabel(
            "F3 hides/restores Metadata Details. Shift+F5 refreshes the active inventory. "
            "Ctrl+L toggles Horizontal/Vertical layout. Ctrl+/ opens Options."
        )
        shortcut_note.setWordWrap(True)
        appearance_layout.addWidget(shortcut_note)
        appearance_layout.addStretch(1)
        tabs.addTab(appearance_page, "Appearance")

        sources_page = QWidget()
        sources_layout = QVBoxLayout(sources_page)
        sources_layout.setContentsMargins(12, 12, 12, 12)
        sources_layout.setSpacing(10)

        sources_heading = QLabel("Data Sources")
        sources_heading_font = sources_heading.font()
        sources_heading_font.setBold(True)
        sources_heading_font.setPointSize(max(sources_heading_font.pointSize(), 11))
        sources_heading.setFont(sources_heading_font)
        sources_layout.addWidget(sources_heading)

        sources_note = QLabel("Linux interfaces used by this read-only TTY/PTY inspector.")
        sources_note.setWordWrap(True)
        sources_layout.addWidget(sources_note)

        sources_text = QTextEdit()
        sources_text.setReadOnly(True)
        sources_text.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        chosen_font = getattr(owner, "_metadata_font", None)
        if chosen_font is not None:
            sources_text.setFont(chosen_font)
            sources_text.document().setDefaultFont(chosen_font)
            sources_text.setCurrentFont(chosen_font)
            font_rule = metadata_font_qss(chosen_font)
        else:
            font_rule = ""
        sources_text.setStyleSheet(
            "QTextEdit { "
            + font_rule
            + " background-color: #151719; color: #dcdcdc; border: 1px solid #333333; }"
        )

        source_key_format = QTextCharFormat()
        source_key_format.setForeground(QColor("#9cdcfe"))
        source_key_format.setFontWeight(600)
        source_value_format = QTextCharFormat()
        source_value_format.setForeground(QColor("#dcdcdc"))
        cursor = sources_text.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        for line in owner.sources_text().splitlines():
            if line and not line[:1].isspace():
                cursor.insertText(line + "\n", source_key_format)
            else:
                cursor.insertText(line + "\n", source_value_format)
        sources_text.setTextCursor(cursor)
        sources_text.moveCursor(QTextCursor.MoveOperation.Start)
        sources_layout.addWidget(sources_text, 1)
        tabs.addTab(sources_page, "Sources")

        export_page = QWidget()
        export_layout = QVBoxLayout(export_page)
        export_layout.setContentsMargins(12, 12, 12, 12)
        export_layout.setSpacing(10)

        export_heading = QLabel("Export details")
        export_heading_font = export_heading.font()
        export_heading_font.setBold(True)
        export_heading.setFont(export_heading_font)
        export_layout.addWidget(export_heading)

        export_note = QLabel(
            f"Select the {owner.current_view} details to include in the export."
        )
        export_note.setWordWrap(True)
        export_layout.addWidget(export_note)

        self.export_checks = []
        for column in owner.columns:
            checkbox = QCheckBox(column[1])
            checkbox.setChecked(True)
            export_layout.addWidget(checkbox)
            self.export_checks.append((checkbox, column))
        self.export_metadata = QCheckBox("Metadata Details")
        self.export_metadata.setChecked(False)
        export_layout.addWidget(self.export_metadata)

        export_layout.addStretch(1)
        export_row = QHBoxLayout()
        export_row.addStretch(1)
        export_button = QPushButton("Export...")
        export_button.clicked.connect(self._export_selected)
        export_row.addWidget(export_button)
        export_layout.addLayout(export_row)
        tabs.addTab(export_page, "Export")

        about_page = QWidget()
        about_layout = QVBoxLayout(about_page)
        about_layout.setContentsMargins(24, 20, 24, 18)
        about_layout.setSpacing(8)

        icon_label = QLabel()
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_label.setFixedSize(112, 112)
        icon_path = Path(__file__).resolve().parent / "icon.png"
        if icon_path.is_file():
            pixmap = QPixmap(str(icon_path))
            if not pixmap.isNull():
                icon_label.setPixmap(
                    pixmap.scaled(
                        112,
                        112,
                        Qt.AspectRatioMode.KeepAspectRatio,
                        Qt.TransformationMode.SmoothTransformation,
                    )
                )
        about_layout.addWidget(icon_label, alignment=Qt.AlignmentFlag.AlignHCenter)

        name = QLabel("<h2 style='margin:0'>TTY Inspector</h2>")
        name.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(name)

        version = QLabel(f"Version {APPLET_VERSION}")
        version.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(version)

        slogan = QLabel("<b>Expose. Explore. Explain.</b>")
        slogan.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(slogan)

        description = QLabel(
            "A read-only LinSpectacles applet for inspecting Linux TTY/PTY devices, "
            "registered terminal infrastructure, active console state, and visible process-to-terminal relationships."
        )
        description.setWordWrap(True)
        description.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(description)

        details = QLabel(
            "<b>Build:</b> Standalone LinSpectacles applet<br>"
            "<b>Organisation ID:</b> <a href='https://github.com/linspectacles/'>linspectacles</a><br>"
            f"<b>Applet ID:</b> {APPLET_ID}"
        )
        details.setWordWrap(True)
        details.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextBrowserInteraction | Qt.TextInteractionFlag.TextSelectableByMouse
        )
        details.setOpenExternalLinks(True)
        details.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(details)

        copyright_label = QLabel(
            "Copyright © 2026 <a href='https://github.com/brunonlinespace'>brunonlinespace</a>"
        )
        copyright_label.setOpenExternalLinks(True)
        copyright_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(copyright_label)

        license_label = QLabel("Licensed under GNU GPLv3 or later.")
        license_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(license_label)

        readme_url = QUrl.fromLocalFile(str(Path(__file__).resolve().parent.parent / "README.md")).toString()
        license_url = QUrl.fromLocalFile(str(Path(__file__).resolve().parent.parent / "LICENSE")).toString()
        links = QLabel(
            f"<a href='{readme_url}'>README</a> &nbsp;·&nbsp; <a href='{license_url}'>License</a> &nbsp;·&nbsp; <a href='{APPLET_REPOSITORY}'>Repository</a>"
        )
        links.setOpenExternalLinks(True)
        links.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(links)
        about_layout.addStretch(1)
        tabs.addTab(about_page, "About")

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)

    def _layout_changed(self, text):
        self.owner.set_details_orientation(str(text).strip().lower(), persist=True)

    def _metadata_panel_changed(self, visible):
        self.owner.set_metadata_panel_visible(bool(visible), persist=True)

    def _export_selected(self):
        selected = [column for checkbox, column in self.export_checks if checkbox.isChecked()]
        include_metadata = self.export_metadata.isChecked()
        if include_metadata:
            selected.append(("metadata_details", "Metadata Details", 520, "left"))
        if not selected:
            QMessageBox.information(self, "Export", "Select at least one detail to export.")
            return

        records = []
        for record in self.owner.get_export_records():
            exported = dict(record)
            if include_metadata:
                exported["metadata_details"] = self.owner.metadata_details_for_export(record)
            records.append(exported)
        if not records:
            QMessageBox.information(self, "Export", "There is no collected data to export yet.")
            return
        path = export_records_dialog(
            self,
            f"{APPLET_NAME} — {self.owner.current_view}",
            records,
            columns=selected,
        )
        if path is not None:
            self.owner.set_status(f"Exported data to {path}")


class TTYInspectorTab(BaseInspectorTab):
    NUMERIC_COLUMNS = set()

    def __init__(self, parent=None):
        initial = VIEW_CONFIG[VIEW_TTY]
        super().__init__(
            initial["total"],
            initial["columns"],
            [initial["selector_all"]],
            parent,
        )
        self.export_title = APPLET_NAME
        self.current_view = VIEW_TTY
        self.view_data = {view: [] for view in VIEWS}
        self.process_scan_stats = {"inaccessible": 0, "vanished": 0, "errors": 0, "error_text": ""}
        self._driver_state = "unavailable"
        self._driver_error = ""
        self._driver_unparsed = 0
        self._ldisc_state = "unavailable"
        self._ldisc_error = ""
        self._ldisc_unparsed = 0
        self._tty_state = "unavailable"
        self._tty_error = ""
        self._pty_sources = {}
        self._pty_node_failures = {"unavailable": 0, "restricted": 0, "error": 0}
        self._host_column_callback = None
        self._hidden_columns_by_view = self._load_view_hidden_columns()

        self.view_label = QLabel("View:")
        self.view_combo = QComboBox()
        self.view_combo.addItems(VIEWS)
        self.view_combo.setMinimumWidth(170)
        # Match Kernel Modules' right-aligned top action group. Place View
        # directly before Refresh List and Options..., after the stretch.
        self.dash_layout.insertWidget(self.dash_layout.indexOf(self.refresh_btn), self.view_label)
        self.dash_layout.insertWidget(self.dash_layout.indexOf(self.refresh_btn), self.view_combo)
        self.view_combo.currentTextChanged.connect(self._view_changed)

        self.details_orientation = "horizontal"
        self._load_details_orientation()
        self.metadata_panel_visible = True
        self._load_metadata_panel_visibility()

        self.export_btn.setText("Options...")
        try:
            self.export_btn.clicked.disconnect()
        except TypeError:
            pass
        self.export_btn.clicked.connect(self.show_options)
        self.export_btn.setEnabled(True)

        self._shortcuts = []
        self._install_shortcuts()

        self._acquire_all()
        self._configure_view(VIEW_TTY)
        self.set_status(self._status_for_view(VIEW_TTY, event="acquired"))

    @staticmethod
    def _column_setting_key(view):
        return f"hidden_columns/{VIEWS.index(view)}"

    def _load_view_hidden_columns(self):
        settings = QSettings("brunonlinespace", "TTY Inspector")
        hidden = {}
        for view in VIEWS:
            key = self._column_setting_key(view)
            if not settings.contains(key):
                continue
            stored = settings.value(key, [])
            if isinstance(stored, str):
                stored = [stored] if stored else []
            hidden[view] = [str(value) for value in (stored or [])]
        return hidden

    def _remember_hidden_columns(self, view, hidden):
        known = {column[0] for column in VIEW_CONFIG[view]["columns"]}
        cleaned = list(dict.fromkeys(value for value in hidden if value in known))
        if self._hidden_columns_by_view.get(view) == cleaned:
            return
        self._hidden_columns_by_view[view] = cleaned
        settings = QSettings("brunonlinespace", "TTY Inspector")
        settings.setValue(self._column_setting_key(view), cleaned)
        settings.sync()

    def _on_columns_changed(self, hidden):
        self._remember_hidden_columns(self.current_view, hidden)
        if callable(self._host_column_callback):
            self._host_column_callback(hidden)

    def apply_host_settings(self, settings=None, column_visibility_callback=None):
        settings = settings or {}
        self._host_column_callback = column_visibility_callback
        # The host has one hidden-column list; import it only when this view
        # has no per-view preference. Never replay another view's stale list.
        if self.current_view not in self._hidden_columns_by_view:
            self._remember_hidden_columns(
                self.current_view, settings.get("hidden_columns", [])
            )
        super().apply_host_settings(settings, None)
        self.column_visibility.apply_hidden(
            self._hidden_columns_by_view.get(self.current_view, [])
        )
        self.column_visibility.set_changed_callback(self._on_columns_changed)

    def _acquire_all(self):
        drivers, state, error, unparsed = _parse_tty_drivers()
        self._driver_state, self._driver_error, self._driver_unparsed = state, error, unparsed
        ttys, self._tty_state, self._tty_error = _collect_tty_devices(drivers)
        ptys, self._pty_sources, self._pty_node_failures = _collect_ptys()
        processes, process_stats = _collect_processes(ttys, ptys)
        _apply_process_counts(ttys, ptys, processes)
        ldiscs, ldisc_state, ldisc_error, ldisc_unparsed = _parse_line_disciplines()
        self._ldisc_state, self._ldisc_error, self._ldisc_unparsed = (
            ldisc_state, ldisc_error, ldisc_unparsed
        )
        self.process_scan_stats = process_stats
        self.view_data[VIEW_DRIVERS] = drivers
        self.view_data[VIEW_TTY] = ttys
        self.view_data[VIEW_PTY] = ptys
        self.view_data[VIEW_PROCESSES] = processes
        self.view_data[VIEW_LDISCS] = ldiscs

    def load_modules(self):
        self.refresh_active_view()

    def refresh_active_view(self):
        view = self.current_view
        if view == VIEW_DRIVERS:
            drivers, state, error, unparsed = _parse_tty_drivers()
            self._driver_state, self._driver_error, self._driver_unparsed = state, error, unparsed
            self.view_data[VIEW_DRIVERS] = drivers
        elif view == VIEW_LDISCS:
            ldiscs, state, error, unparsed = _parse_line_disciplines()
            self._ldisc_state, self._ldisc_error, self._ldisc_unparsed = state, error, unparsed
            self.view_data[VIEW_LDISCS] = ldiscs
        else:
            drivers, state, error, unparsed = _parse_tty_drivers()
            self._driver_state, self._driver_error, self._driver_unparsed = state, error, unparsed
            ttys, self._tty_state, self._tty_error = _collect_tty_devices(drivers)
            ptys, self._pty_sources, self._pty_node_failures = _collect_ptys()
            processes, process_stats = _collect_processes(ttys, ptys)
            _apply_process_counts(ttys, ptys, processes)
            self.process_scan_stats = process_stats
            self.view_data[VIEW_DRIVERS] = drivers
            self.view_data[VIEW_TTY] = ttys
            self.view_data[VIEW_PTY] = ptys
            self.view_data[VIEW_PROCESSES] = processes

        self.modules_data = self.view_data.get(view, [])
        self._populate_selector()
        self.filter_modules()
        self.set_status(self._status_for_view(view, event="refreshed"))

    def _view_changed(self, view):
        if view not in VIEW_CONFIG:
            return
        if view != self.current_view:
            self._remember_hidden_columns(
                self.current_view, self.column_visibility.hidden_columns()
            )
        self._configure_view(view)
        self.set_status(self._status_for_view(view, event="showing"))

    def _configure_view(self, view):
        config = VIEW_CONFIG[view]
        self.current_view = view
        self.columns = list(config["columns"])
        self.NUMERIC_COLUMNS = set(config["numeric"])
        self.total_label_text = config["total"]
        self.modules_data = self.view_data.get(view, [])
        self.stats_label.setText(f"{self.total_label_text}: {len(self.modules_data)}")

        self.table.setColumnCount(len(self.columns))
        self.table.setHorizontalHeaderLabels([column[1] for column in self.columns])
        for index, (_column_id, _label, width, _alignment) in enumerate(self.columns):
            self.table.setColumnWidth(index, width)
            self.table.setColumnHidden(index, False)
        self.column_visibility.columns = list(self.columns)
        self.column_visibility.apply_hidden(self._hidden_columns_by_view.get(view, []))
        self.column_visibility.set_changed_callback(self._on_columns_changed)

        selector_label = config.get("selector_label")
        self.category_label.setVisible(bool(selector_label))
        self.category_dropdown.setVisible(bool(selector_label))
        if selector_label:
            self.category_label.setText(selector_label)
        self._populate_selector()
        self.filter_modules()

    def _populate_selector(self):
        config = VIEW_CONFIG[self.current_view]
        selector_key = config.get("selector_key")
        selector_all = config.get("selector_all")
        if not selector_key or not selector_all:
            return
        current = self.category_dropdown.currentText()
        values = sorted(
            {
                str(record.get(selector_key, "")).strip()
                for record in self.view_data.get(self.current_view, [])
                if str(record.get(selector_key, "")).strip()
            },
            key=str.lower,
        )
        blocked = self.category_dropdown.blockSignals(True)
        try:
            self.category_dropdown.clear()
            self.category_dropdown.addItem(selector_all)
            self.category_dropdown.addItems(values)
            if current in values or current == selector_all:
                self.category_dropdown.setCurrentText(current)
            else:
                self.category_dropdown.setCurrentIndex(0)
        finally:
            self.category_dropdown.blockSignals(blocked)

    def filter_modules(self, *_):
        config = VIEW_CONFIG[self.current_view]
        query = self.search_entry.text().strip().lower()
        selector_key = config.get("selector_key")
        selector_all = config.get("selector_all")
        selected = self.category_dropdown.currentText() if selector_key else ""

        matches = []
        for record in self.view_data.get(self.current_view, []):
            match_selector = True
            if selector_key:
                match_selector = selected == selector_all or str(record.get(selector_key, "")) == selected
            match_query = not query or any(
                query in str(value).lower()
                for key, value in record.items()
                if not str(key).startswith("_")
            )
            if match_selector and match_query:
                matches.append(record)

        blocked = self.table.blockSignals(True)
        try:
            self.clear_info()
            self.table.clearSelection()
            self.table.setCurrentCell(-1, -1)
            self.table.setSortingEnabled(False)
            self.table.setRowCount(len(matches))
            for row, record in enumerate(matches):
                for column_index, (column_id, _label, _width, alignment) in enumerate(self.columns):
                    value = record.get(column_id, "")
                    display = f"{value:,}" if column_id in self.NUMERIC_COLUMNS and isinstance(value, int) else str(value)
                    from PyQt6.QtWidgets import QTableWidgetItem
                    item = QTableWidgetItem(display)
                    if column_index == 0:
                        item.setData(Qt.ItemDataRole.UserRole, record)
                    if alignment == "right":
                        item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                    else:
                        item.setTextAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
                    self.table.setItem(row, column_index, item)
            if matches:
                self.table.setCurrentCell(0, 0)
                self.table.selectRow(0)
        finally:
            self.table.blockSignals(blocked)

        if matches:
            self.on_module_select()
        else:
            self.clear_info()

        self.stats_label.setText(f"{self.total_label_text}: {len(self.view_data.get(self.current_view, []))}")
        filtered = bool(query) or (selector_key and selected != selector_all)
        if filtered:
            self.filter_status_lbl.setText(
                f"(Showing {len(matches)} of {len(self.view_data.get(self.current_view, []))} items)"
            )
        else:
            self.filter_status_lbl.clear()

    def sort_by(self, column_id):
        reverse = self._sort_reverse.get(f"{self.current_view}:{column_id}", False)
        records = self.view_data.get(self.current_view, [])
        if column_id in self.NUMERIC_COLUMNS:
            def key_func(item):
                value = item.get(column_id, 0)
                return value if isinstance(value, (int, float)) else -1
        else:
            key_func = lambda item: str(item.get(column_id, "")).lower()
        records.sort(key=key_func, reverse=reverse)
        self._sort_reverse[f"{self.current_view}:{column_id}"] = not reverse
        self.modules_data = records
        self.filter_modules()

    def on_module_select(self):
        record = self.current_record()
        if not record:
            return
        self._render_record_details(record, self.current_view)
        identity = self._record_identity(record, self.current_view)
        self.set_status(f"Inspecting {self.current_view}: {identity}.")

    @staticmethod
    def _record_identity(record, view):
        key_by_view = {
            VIEW_TTY: "tty",
            VIEW_PTY: "pty",
            VIEW_DRIVERS: "driver",
            VIEW_LDISCS: "line_discipline",
            VIEW_PROCESSES: "process",
        }
        value = record.get(key_by_view.get(view, ""), "")
        if view == VIEW_PROCESSES:
            return f"{value} (PID {record.get('pid', '')})"
        return str(value)

    def _render_record_details(self, record, view):
        self.clear_info()
        if view == VIEW_TTY:
            self.append_info("--- TTY Device ---\n")
            self.append_key_value("TTY", record.get("tty", ""))
            self.append_key_value("Device Path", record.get("device_path", ""))
            self.append_key_value("Major:Minor", record.get("major_minor", ""))
            self.append_key_value("Driver / Type", record.get("driver_type", ""))
            self.append_key_value("Active", record.get("active", ""))
            self.append_key_value("Console", record.get("console", ""))
            self.append_key_value("Visible Processes with Controlling TTY", record.get("process_count", 0))

            self.append_info("\n--- Sysfs Relationship ---\n")
            self.append_key_value("Sysfs Path", record.get("_sysfs_path", ""))
            self.append_key_value("Backing Device", record.get("_backing_device") or "Not exposed")
            self.append_key_value("Sysfs Driver", record.get("_sysfs_driver") or "Not exposed")
            self.append_key_value("TTY Driver (/proc/tty/drivers)", record.get("_proc_driver") or "Not matched")
            self.append_key_value("TTY Type (/proc/tty/drivers)", record.get("_proc_type") or "Not matched")
            if record.get("_modalias"):
                self.append_key_value("Modalias", record.get("_modalias"))
            if record.get("_uevent"):
                self.append_info("\n--- Device Uevent Attributes ---\n")
                for line in str(record.get("_uevent", "")).splitlines():
                    if "=" in line:
                        key, value = line.split("=", 1)
                        self.append_key_value(key, value)
                    elif line:
                        self.append_info(line + "\n")

            self.append_info("\n--- Active Console Evidence ---\n")
            for path, (state, value) in record.get("_active_sources", {}).items():
                if state == "observed":
                    shown = value or "(empty)"
                elif state == "restricted":
                    shown = "Restricted"
                elif state == "unavailable":
                    shown = "Not exposed"
                else:
                    shown = f"Error: {value}"
                self.append_key_value(path, shown)
            self.append_info(
                "Active is Yes only for TTYs listed in observed active-console data; "
                "No means not listed in available nonempty data; Unknown means no such data was readable.\n"
            )
            if record.get("tty") == "ptmx":
                self.append_info(
                    "Overlap note: ptmx is a kernel TTY-class entry and is also listed in "
                    "the PTYs view as the PTY master multiplexer; this is not a second PTY.\n"
                )

            self.append_info("\n--- Provenance ---\n")
            self.append_key_value("Identity / device number", "/sys/class/tty/<tty>/dev")
            self.append_key_value("Device relationship", "/sys/class/tty/<tty>/device")
            self.append_key_value("TTY driver registry", "/proc/tty/drivers")
            self.append_key_value("Process count", "/proc/<pid>/stat")

        elif view == VIEW_PTY:
            self.append_info("--- Pseudo-Terminal Endpoint ---\n")
            self.append_key_value("PTY", record.get("pty", ""))
            self.append_key_value("Role", record.get("role", ""))
            self.append_key_value("Device Path", record.get("device_path", ""))
            self.append_key_value("Major:Minor", record.get("major_minor", ""))
            self.append_key_value("Visible Processes with Controlling TTY", record.get("visible_processes", 0))
            self.append_key_value("Representative PID", record.get("representative_pid") or "None")
            self.append_info("\n--- Provenance ---\n")
            self.append_key_value("Endpoint inventory", record.get("_source", ""))
            self.append_key_value("Device number", "stat(2) metadata only; the terminal device is not opened")
            self.append_key_value("Process association", "/proc/<pid>/stat controlling-terminal device number")
            self.append_info(
                "Relationship note: TTY Inspector does not infer a per-PTY master/slave pairing. "
                "Numeric /dev/pts entries are reported as devpts slave devices; /dev/ptmx is reported only as the master multiplexer. "
                "The ptmx endpoint may also appear under TTY Devices from /sys/class/tty: that is the same endpoint "
                "shown in two inventory contexts, not a second PTY.\n"
            )

        elif view == VIEW_DRIVERS:
            self.append_info("--- Registered TTY Driver ---\n")
            self.append_key_value("Driver", record.get("driver", ""))
            self.append_key_value("Device Prefix", record.get("device_prefix", ""))
            self.append_key_value("Major", record.get("major", ""))
            self.append_key_value("Minor Range", record.get("minor_range", ""))
            self.append_key_value("Type", record.get("type", ""))
            self.append_info("\n--- Provenance ---\n")
            self.append_key_value("Source", "/proc/tty/drivers")
            self.append_key_value("Kernel-reported record", record.get("_source_line", ""))
            self.append_info("Type is preserved exactly as reported by the kernel TTY driver registry.\n")

        elif view == VIEW_LDISCS:
            self.append_info("--- Registered Line Discipline ---\n")
            self.append_key_value("Line Discipline", record.get("line_discipline", ""))
            self.append_key_value("Number / Identifier", record.get("identifier", ""))
            self.append_info("\n--- Provenance ---\n")
            self.append_key_value("Source", "/proc/tty/ldiscs")
            self.append_key_value("Kernel-reported record", record.get("_source_line", ""))
            self.append_info(
                "Registry-state note: presence here means the line discipline is registered; "
                "it is not proof that the discipline is attached to any particular TTY.\n"
            )

        elif view == VIEW_PROCESSES:
            self.append_info("--- Visible Process with Controlling Terminal ---\n")
            self.append_key_value("Process", record.get("process", ""))
            self.append_key_value("PID", record.get("pid", ""))
            self.append_key_value("UID / User", record.get("uid_user", ""))
            self.append_key_value("TTY", record.get("tty", ""))
            self.append_key_value("TTY Device Number", f"{record.get('_tty_major')}:{record.get('_tty_minor')}")
            self.append_key_value("Session ID", record.get("session_id", ""))
            self.append_key_value("Process Group", record.get("process_group", ""))
            self.append_key_value("State", record.get("state", ""))
            self.append_info("\n--- Provenance ---\n")
            self.append_key_value("Process / TTY / session / process group / state", f"/proc/{record.get('pid')}/stat")
            self.append_key_value("UID", f"/proc/{record.get('pid')}/status")
            self.append_info(
                "Only process information visible to the current user is reported. Process disappearance during acquisition is treated as normal churn.\n"
            )

        self.info_text.moveCursor(QTextCursor.MoveOperation.Start)

    def metadata_details_for_export(self, record):
        original_info = self.info_text
        temp = QTextEdit()
        self.info_text = temp
        try:
            self._render_record_details(record, self.current_view)
            return temp.toPlainText()
        finally:
            self.info_text = original_info

    def get_export_records(self):
        return list(self.view_data.get(self.current_view, []))

    def show_options(self):
        dialog = TTYInspectorOptionsDialog(self)
        dialog.exec()

    @staticmethod
    def sources_text():
        return (
            "TTY Inspector is read-only. It never opens terminal devices for interactive I/O and performs no privilege escalation.\n\n"
            "TTY driver registry\n"
            "  /proc/tty/drivers\n\n"
            "Line-discipline registry\n"
            "  /proc/tty/ldiscs\n\n"
            "TTY device identity, device numbers, backing relationships and active-console attributes\n"
            "  /sys/class/tty/\n\n"
            "Terminal device-node presence and device numbers\n"
            "  /dev/tty*\n"
            "  /dev/ptmx\n"
            "  /dev/pts/\n\n"
            "Visible process controlling-terminal, session, process-group and state information\n"
            "  /proc/<pid>/stat\n\n"
            "Visible process UID information\n"
            "  /proc/<pid>/status\n\n"
            "Important distinctions\n"
            "  /proc/tty/ldiscs is registry state; it does not prove attachment to a particular TTY.\n"
            "  Numeric /dev/pts nodes are reported as devpts slave devices; TTY Inspector does not invent per-PTY master/slave pairings.\n"
            "  ptmx may appear in both TTY Devices (sysfs TTY class) and PTYs (master multiplexer); it is one endpoint represented in different inventories, not two PTYs.\n"
            "  Process counts mean visible processes whose controlling-terminal device number matches the endpoint, not all processes with open TTY file descriptors.\n"
            "  Unrecognised nonblank driver and line-discipline registry lines are counted as unparsed records, not invented entries.\n"
            "  Process churn is expected during acquisition and vanished processes are counted rather than treated as a crash.\n"
            "  No TTY is written, configured, allocated, destroyed, attached, detached, or used to send input/output."
        )

    def _status_for_view(self, view, *, event="refreshed"):
        count = len(self.view_data.get(view, []))
        prefix = {"acquired": "Acquired", "refreshed": "Refreshed", "showing": "Showing"}[event]
        suffix_parts = []

        if view == VIEW_TTY and self._tty_state != "observed":
            source = f"/sys/class/tty {self._tty_state}"
            if self._tty_error:
                source += f" ({self._tty_error})"
            suffix_parts.append(source)
        if view == VIEW_PTY:
            for path, (state, error) in self._pty_sources.items():
                if state != "observed":
                    source = f"{path} {state}"
                    if error:
                        source += f" ({error})"
                    suffix_parts.append(source)
            for state, count_failed in self._pty_node_failures.items():
                if count_failed:
                    suffix_parts.append(f"{count_failed} /dev/pts node(s) {state}")
        if view == VIEW_DRIVERS:
            if self._driver_state != "observed":
                source = f"/proc/tty/drivers {self._driver_state}"
                if self._driver_error:
                    source += f" ({self._driver_error})"
                suffix_parts.append(source)
            if self._driver_unparsed:
                suffix_parts.append(f"{self._driver_unparsed} unparsed registry record(s)")
        if view == VIEW_LDISCS:
            if self._ldisc_state != "observed":
                source = f"/proc/tty/ldiscs {self._ldisc_state}"
                if self._ldisc_error:
                    source += f" ({self._ldisc_error})"
                suffix_parts.append(source)
            if self._ldisc_unparsed:
                suffix_parts.append(f"{self._ldisc_unparsed} unparsed registry record(s)")
        if view in {VIEW_TTY, VIEW_PTY, VIEW_PROCESSES}:
            stats = self.process_scan_stats
            if stats.get("inaccessible"):
                suffix_parts.append(f"{stats['inaccessible']} inaccessible process(es)")
            if stats.get("vanished"):
                suffix_parts.append(f"{stats['vanished']} vanished during scan")
            if stats.get("errors"):
                suffix_parts.append(f"{stats['errors']} process read error(s)")

        suffix = "; " + "; ".join(suffix_parts) if suffix_parts else ""
        return f"{prefix} {view}: {count} item(s){suffix}."

    def _add_shortcut(self, sequence, callback):
        shortcut = QShortcut(QKeySequence(sequence), self)
        shortcut.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
        shortcut.activated.connect(callback)
        self._shortcuts.append(shortcut)
        return shortcut

    def _install_shortcuts(self):
        self._add_shortcut("F3", self.toggle_metadata_panel)
        self._add_shortcut("Ctrl+L", self.toggle_details_orientation)
        self._add_shortcut("Ctrl+/", self.show_options)
        self._add_shortcut("Shift+F5", self.refresh_active_view)

    def toggle_details_orientation(self):
        target = "vertical" if self.details_orientation == "horizontal" else "horizontal"
        self.set_details_orientation(target, persist=True)

    def _load_metadata_panel_visibility(self):
        settings = QSettings("brunonlinespace", "TTY Inspector")
        value = settings.value("metadata_panel_visible", True)
        if isinstance(value, str):
            visible = value.strip().lower() not in {"0", "false", "no", "off"}
        else:
            visible = bool(value)
        self.set_metadata_panel_visible(visible, persist=False)

    def set_metadata_panel_visible(self, visible, *, persist=True):
        self.metadata_panel_visible = bool(visible)
        details_panel = self.splitter.widget(1)
        if details_panel is not None:
            details_panel.setVisible(self.metadata_panel_visible)
        if self.metadata_panel_visible:
            self.set_details_orientation(self.details_orientation, persist=False)
        if persist:
            settings = QSettings("brunonlinespace", "TTY Inspector")
            settings.setValue("metadata_panel_visible", self.metadata_panel_visible)
            settings.sync()

    def toggle_metadata_panel(self):
        self.set_metadata_panel_visible(not self.metadata_panel_visible, persist=True)

    def _load_details_orientation(self):
        settings = QSettings("brunonlinespace", "TTY Inspector")
        orientation = str(settings.value("details_orientation", "horizontal") or "horizontal").lower()
        if orientation not in {"horizontal", "vertical"}:
            orientation = "horizontal"
        self.set_details_orientation(orientation, persist=False)

    def set_details_orientation(self, orientation, *, persist=True):
        orientation = str(orientation or "horizontal").lower()
        if orientation not in {"horizontal", "vertical"}:
            orientation = "horizontal"
        self.details_orientation = orientation
        details_panel = self.splitter.widget(1)
        details_layout = details_panel.layout() if details_panel is not None else None
        if orientation == "vertical":
            self.splitter.setOrientation(Qt.Orientation.Vertical)
            if details_layout is not None:
                details_layout.setContentsMargins(0, 8, 0, 0)
            self.splitter.setSizes([430, 330])
        else:
            self.splitter.setOrientation(Qt.Orientation.Horizontal)
            if details_layout is not None:
                details_layout.setContentsMargins(8, 0, 0, 0)
            self.splitter.setSizes([480, 700])
        if persist:
            settings = QSettings("brunonlinespace", "TTY Inspector")
            settings.setValue("details_orientation", orientation)
            settings.sync()


def create_applet(parent=None):
    return TTYInspectorTab(parent=parent)


def run_standalone():
    import sys
    from PyQt6.QtGui import QIcon
    from PyQt6.QtWidgets import QApplication, QMainWindow
    from ._support import STANDALONE_STYLESHEET

    app = QApplication(sys.argv)
    app.setApplicationName(APPLET_NAME)
    app.setOrganizationName(APPLET_AUTHOR)
    icon_path = Path(__file__).resolve().parent / "icon.png"
    if icon_path.is_file():
        app.setWindowIcon(QIcon(str(icon_path)))
    app.setStyleSheet(STANDALONE_STYLESHEET)
    window = QMainWindow()
    if icon_path.is_file():
        window.setWindowIcon(QIcon(str(icon_path)))
    window.setWindowTitle(f"{APPLET_NAME} {APPLET_VERSION} — LinSpectacles Applet")
    window.resize(1200, 780)
    window.setCentralWidget(create_applet())
    window.show()
    return app.exec()
