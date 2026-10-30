# PrivacyLens Chrome extension

## Local installation

1. Start the local server from the project root:

   ```powershell
   python app.py
   ```

2. Open Chrome and visit `chrome://extensions`.
3. Enable **Developer mode**.
4. Click **Load unpacked** and choose this `extension` folder.
5. Pin **PrivacyLens Local Guard** from the extensions menu.

## Demo flow

1. Open any page containing synthetic sensitive data, or open the PrivacyLens dashboard.
2. Click the PrivacyLens extension icon.
3. Click **Scan active page**.
4. Review the detected patterns and sanitized context.
5. Enter an action target such as `Pay now`.
6. Click **Check proposed action**. Payment/destructive actions should return `APPROVAL_REQUIRED`; prompt injection or secret-bearing action values should return `BLOCK`.

The extension sends page text only to `127.0.0.1:8765`, where the local sanitizer and action guard run. It does not call a cloud model or transmit page data to a third party.

