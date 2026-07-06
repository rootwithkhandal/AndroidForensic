from . import __app_name__, __license__, __website__, __version__


def about_text():
    """Returns the about message as a string (interface-agnostic)."""
    return (
        f"About {__app_name__}\n"
        f"Version: {__version__}\n"
        f"License: {__license__}\n"
        f"Copyright \u00A9 2012-2026\n"
        f"Website: {__website__}"
    )


def backup_instructions():
    """Returns backup instruction text."""
    return (
        "Attention!\n"
        "1. Unlock the screen;\n"
        '2. Tap on "Back up my data".\n'
        "Click OK to Continue\n"
        "(Extraction may take some time..)"
    )


def screen_guide_text():
    """Returns screen capture usage guide text."""
    return """\
USAGE INSTRUCTIONS
- Works with Android versions 4.x and above.
- Connect a device via cable with USB debugging enabled.
- Press [Capture] to take a screen shot.
- Single captures can be saved.

REPORTING
- Select an output directory.
- Custom comments can be added with each capture.
- Tick [Remember] to reuse last comment.
- Captures can be taken just by pressing <Enter>.
- Press [Report] to generate and open a HTML report."""


content_protect = "** Content Protection Enabled! **\nIt is not possible to capture this type of content."


GUIDE_WA = """
This utility will decode multiple WhatsApp databases and produce combined messages on one report (without duplicates).
Use recovered and decrypted backup databases.

Instructions: Browse and select the folder with all "msgstore.db" (unencrypted and/or decrypted) databases.
"""


def select_output_text():
    """Returns output selection warning text."""
    return "Select the 'Output' directory first!"


def device_not_detected_text():
    """Returns device not detected warning text."""
    return (
        "Device not detected!\n"
        "- Is an Android device connected?\n"
        "- Is USB Debugging enabled?\n"
        "- Are device Drivers installed?\n"
        "- Did you accept the RSA fingerprint?"
    )


def license_applied_text(exp):
    """Returns license applied success text."""
    return (
        f"License code successfully written!\n"
        f"Expiry date:{exp}\n"
        f"Please restart AndroidForensic Everywhere."
    )
