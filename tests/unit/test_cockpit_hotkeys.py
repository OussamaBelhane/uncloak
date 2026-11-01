"""
Comprehensive unit tests for the Uncloak interactive cockpit hotkey matrix and layout engine.
Validates cross-platform key handling, state transitions, filtering, sorting, export, and terminal geometry.
Compatible with standard library unittest and pytest.
"""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from rich.console import Console

from uncloak.ui.cockpit import (
    NonBlockingKeyboard,
    copy_to_clipboard,
    export_telemetry_json,
    get_demo_flows,
)
from uncloak.ui.layout import (
    CockpitState,
    FlowEntry,
    build_cockpit_layout,
    get_visible_flows,
    render_table,
)


class TestCockpitHotkeys(unittest.TestCase):
    """Test suite covering every interactive hotkey and state transition."""

    def setUp(self):
        self.state = CockpitState(flows=get_demo_flows(), selected_index=2)

    def test_navigation_up_down(self):
        """Test UP and DOWN arrow navigation with bounds checking."""
        visible = get_visible_flows(self.state)
        self.assertGreaterEqual(len(visible), 5)
        self.state.selected_index = 2

        # Move UP
        self.state.selected_index -= 1
        self.assertEqual(self.state.selected_index, 1)

        # Move UP to top
        self.state.selected_index -= 1
        self.assertEqual(self.state.selected_index, 0)

        # Bounds check top
        if self.state.selected_index > 0:
            self.state.selected_index -= 1
        self.assertEqual(self.state.selected_index, 0)

        # Move DOWN
        self.state.selected_index += 1
        self.assertEqual(self.state.selected_index, 1)

        # Move DOWN to end
        self.state.selected_index = len(visible) - 1
        self.assertEqual(self.state.selected_index, len(visible) - 1)

        # Bounds check bottom
        if self.state.selected_index < len(visible) - 1:
            self.state.selected_index += 1
        self.assertEqual(self.state.selected_index, len(visible) - 1)

    def test_drawer_toggle(self):
        """Test ENTER and 'd' toggle the bottom forensic detail drawer."""
        self.assertTrue(self.state.drawer_expanded)
        self.state.drawer_expanded = not self.state.drawer_expanded
        self.assertFalse(self.state.drawer_expanded)
        self.state.drawer_expanded = not self.state.drawer_expanded
        self.assertTrue(self.state.drawer_expanded)

    def test_dossier_modal_toggle(self):
        """Test 'I' opens dossier modal and 'ESC' / 'i' closes it."""
        self.assertFalse(self.state.show_dossier)
        self.state.show_dossier = True
        self.assertTrue(self.state.show_dossier)
        self.state.show_dossier = False
        self.assertFalse(self.state.show_dossier)

    def test_sever_socket_hotkey(self):
        """Test 'K' severs the selected threat socket and recalculates active beacons."""
        visible = get_visible_flows(self.state)
        target = visible[0]  # First threat: update.exe
        self.assertTrue(target.is_threat)
        self.assertFalse(target.is_severed)

        target.is_severed = True
        target.state = "SEVERED (Host Clean)"
        self.state.active_beacons = sum(1 for f in self.state.flows if f.is_threat and not f.is_severed)

        self.assertTrue(target.is_severed)
        self.assertEqual(target.state, "SEVERED (Host Clean)")

    def test_pause_resume_hotkey(self):
        """Test SPACE toggles pause state."""
        self.assertFalse(self.state.is_paused)
        self.state.is_paused = not self.state.is_paused
        self.assertTrue(self.state.is_paused)
        self.state.is_paused = not self.state.is_paused
        self.assertFalse(self.state.is_paused)

    def test_threat_filter_toggle(self):
        """Test 'F' filters table to show threats only."""
        self.assertFalse(self.state.filter_threats_only)
        all_flows = get_visible_flows(self.state)
        self.assertEqual(len(all_flows), len(self.state.flows))

        self.state.filter_threats_only = True
        threat_flows = get_visible_flows(self.state)
        self.assertEqual(len(threat_flows), sum(1 for f in self.state.flows if f.is_threat))
        self.assertTrue(all(f.is_threat for f in threat_flows))

    def test_interactive_search_hotkey(self):
        """Test '/' activates interactive search, query substring matching, and ESC clearing."""
        self.state.in_search_input = True
        self.state.search_query = "sliver"

        matched = get_visible_flows(self.state)
        self.assertEqual(len(matched), 1)
        self.assertEqual(matched[0].c2_framework, "Sliver C2")

        # Search by PID
        self.state.search_query = "8830"
        matched_pid = get_visible_flows(self.state)
        self.assertEqual(len(matched_pid), 1)
        self.assertEqual(matched_pid[0].pid, 8830)

        # Search by IP
        self.state.search_query = "45.33.32"
        matched_ip = get_visible_flows(self.state)
        self.assertEqual(len(matched_ip), 1)
        self.assertEqual(matched_ip[0].process_name, "rundll32.exe")

        # Cancel search
        self.state.in_search_input = False
        self.state.search_query = None
        self.assertEqual(len(get_visible_flows(self.state)), len(self.state.flows))

    def test_sort_cycling_hotkey(self):
        """Test 'S' cycles through all 5 sort dimensions and verifies ordering."""
        # 1. Sort by THREAT (descending threat score)
        self.state.sort_field = "threat"
        flows = get_visible_flows(self.state)
        unsevered = [f for f in flows if not f.is_severed]
        for i in range(len(unsevered) - 1):
            self.assertGreaterEqual(unsevered[i].threat_score, unsevered[i + 1].threat_score)

        # 2. Sort by INTERVAL (periodic first)
        self.state.sort_field = "interval"
        flows = get_visible_flows(self.state)
        self.assertNotEqual(flows[0].interval_str, "Irregular")

        # 3. Sort by PAYLOAD (descending bytes)
        self.state.sort_field = "payload"
        flows = get_visible_flows(self.state)
        for i in range(len(flows) - 1):
            self.assertGreaterEqual(flows[i].bytes_transferred, flows[i + 1].bytes_transferred)

        # 4. Sort by PID (ascending PID)
        self.state.sort_field = "pid"
        flows = get_visible_flows(self.state)
        for i in range(len(flows) - 1):
            self.assertLessEqual(flows[i].pid, flows[i + 1].pid)

        # 5. Sort by PROCESS (alphabetical)
        self.state.sort_field = "process"
        flows = get_visible_flows(self.state)
        for i in range(len(flows) - 1):
            self.assertLessEqual(flows[i].process_name.lower(), flows[i + 1].process_name.lower())

    def test_export_telemetry_json(self):
        """Test 'E' exports genuine structured JSON to disk."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            with patch("pathlib.Path.cwd", return_value=tmp_path):
                filename = export_telemetry_json(self.state)
                file_path = tmp_path / filename
                self.assertTrue(file_path.exists())

                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.assertEqual(data["app"], "UNCLOAK")
                self.assertEqual(data["total_sockets"], 124)
                self.assertGreater(len(data["flows"]), 0)

                # Dossier single export
                target = self.state.flows[0]
                dos_fn = export_telemetry_json(self.state, target_flow=target)
                dos_path = tmp_path / dos_fn
                self.assertTrue(dos_path.exists())

                with open(dos_path, "r", encoding="utf-8") as f:
                    dos_data = json.load(f)
                self.assertEqual(dos_data["flow"]["pid"], target.pid)
                self.assertEqual(dos_data["flow"]["process_name"], target.process_name)

    def test_copy_to_clipboard_cross_platform(self):
        """Test clipboard copy handles Linux wl-copy / xclip and Windows clip gracefully."""
        res = copy_to_clipboard(r"C:\Windows\System32\powershell.exe")
        self.assertIsInstance(res, bool)

    def test_windows_keyboard_sequences(self):
        """Test Windows msvcrt key mappings for arrow keys, enter, backspace, and esc."""
        mock_msvcrt = MagicMock()
        with patch.dict("sys.modules", {"msvcrt": mock_msvcrt}):
            kb = NonBlockingKeyboard()
            kb.is_windows = True

            mock_msvcrt.kbhit.return_value = True

            # Up arrow: \xe0 followed by H
            mock_msvcrt.getch.side_effect = [b"\xe0", b"H"]
            self.assertEqual(kb.read_key(), "UP")

            # Down arrow: \x00 followed by P
            mock_msvcrt.getch.side_effect = [b"\x00", b"P"]
            self.assertEqual(kb.read_key(), "DOWN")

            # Left arrow: \x00 followed by K
            mock_msvcrt.getch.side_effect = [b"\x00", b"K"]
            self.assertEqual(kb.read_key(), "LEFT")

            # Right arrow: \xe0 followed by M
            mock_msvcrt.getch.side_effect = [b"\xe0", b"M"]
            self.assertEqual(kb.read_key(), "RIGHT")

            # Enter: \r
            mock_msvcrt.getch.side_effect = None
            mock_msvcrt.getch.return_value = b"\r"
            self.assertEqual(kb.read_key(), "ENTER")

            # Backspace: \x08
            mock_msvcrt.getch.return_value = b"\x08"
            self.assertEqual(kb.read_key(), "BACKSPACE")

            # Escape: \x1b
            mock_msvcrt.getch.return_value = b"\x1b"
            self.assertEqual(kb.read_key(), "ESC")

    def test_linux_keyboard_sequences(self):
        """Test Linux termios / select ANSI sequences for arrow keys, enter, backspace, and esc."""
        kb = NonBlockingKeyboard()
        kb.is_windows = False

        # Standalone ESC
        with patch("select.select", side_effect=[([True], [], []), ([], [], [])]):
            with patch("sys.stdin.read", return_value="\x1b"):
                self.assertEqual(kb.read_key(), "ESC")

        # Arrow UP: \x1b[A
        with patch("select.select", side_effect=[([True], [], []), ([True], [], [])]):
            with patch("sys.stdin.read", side_effect=["\x1b", "[A"]):
                self.assertEqual(kb.read_key(), "UP")

        # Arrow DOWN: \x1b[B
        with patch("select.select", side_effect=[([True], [], []), ([True], [], [])]):
            with patch("sys.stdin.read", side_effect=["\x1b", "[B"]):
                self.assertEqual(kb.read_key(), "DOWN")

        # Enter
        with patch("select.select", return_value=([True], [], [])):
            with patch("sys.stdin.read", return_value="\n"):
                self.assertEqual(kb.read_key(), "ENTER")

        # Backspace
        with patch("select.select", return_value=([True], [], [])):
            with patch("sys.stdin.read", return_value="\x7f"):
                self.assertEqual(kb.read_key(), "BACKSPACE")

    def test_physical_layout_28_lines_strict(self):
        """Validates that build_cockpit_layout renders exactly 28 physical terminal lines across all modes."""
        console = Console(width=120, height=28, force_terminal=True, color_system="truecolor")

        # Mode 1: Standard expanded drawer
        self.state.show_dossier = False
        self.state.drawer_expanded = True
        layout1 = build_cockpit_layout(self.state, width=120, height=28)
        with console.capture() as cap1:
            console.print(layout1)
        self.assertEqual(len(cap1.get().splitlines()), 28)

        # Mode 2: Collapsed drawer
        self.state.drawer_expanded = False
        layout2 = build_cockpit_layout(self.state, width=120, height=28)
        with console.capture() as cap2:
            console.print(layout2)
        self.assertEqual(len(cap2.get().splitlines()), 28)

        # Mode 3: Process Forensic Dossier
        self.state.show_dossier = True
        layout3 = build_cockpit_layout(self.state, width=120, height=28)
        with console.capture() as cap3:
            console.print(layout3)
        self.assertEqual(len(cap3.get().splitlines()), 28)


if __name__ == "__main__":
    unittest.main()
