/* AndroidForensic Everywhere - Client-Side Interactive Logic */

document.addEventListener("DOMContentLoaded", () => {
  initDevicePolling();
  initLogStreaming();
  initTabs();
  initFormHandlers();
});

/* --- Real-Time Device Polling --- */
function initDevicePolling() {
  const statusDot = document.getElementById("device-status-dot");
  const statusText = document.getElementById("device-status-text");

  async function checkDevice() {
    try {
      const res = await fetch("/api/device/status");
      const data = await res.json();
      
      if (data.connected && data.serial !== "No Device") {
        if (statusDot) statusDot.className = "status-dot connected";
        if (statusText) statusText.textContent = `${data.serial} (${data.privilege.toUpperCase()})`;
      } else {
        if (statusDot) statusDot.className = "status-dot disconnected";
        if (statusText) statusText.textContent = "No Device Connected";
      }
    } catch (err) {
      if (statusDot) statusDot.className = "status-dot disconnected";
      if (statusText) statusText.textContent = "Connection Error";
    }
  }

  checkDevice();
  setInterval(checkDevice, 5000);
}

/* --- Server-Sent Events (SSE) Live Log Streaming --- */
function initLogStreaming() {
  const logContainer = document.getElementById("console-log-container");
  if (!logContainer) return;

  const evtSource = new EventSource("/api/logs/stream");
  evtSource.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      if (data.level === "ping") return;

      const entry = document.createElement("div");
      entry.className = `log-entry log-${data.level}`;
      entry.innerHTML = `<span class="log-time">[${data.time}]</span><span>${data.msg}</span>`;
      
      logContainer.appendChild(entry);
      logContainer.scrollTop = logContainer.scrollHeight;
    } catch (e) {
      console.error("Error parsing log event:", e);
    }
  };
}

/* --- Tab Switching Logic --- */
function initTabs() {
  const tabButtons = document.querySelectorAll(".tab-btn");
  tabButtons.forEach(btn => {
    btn.addEventListener("click", () => {
      const targetId = btn.getAttribute("data-tab");
      const tabGroup = btn.closest(".card") || document;

      tabGroup.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
      tabGroup.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));

      btn.classList.add("active");
      const content = document.getElementById(targetId);
      if (content) content.classList.add("active");
    });
  });
}

/* --- Form Submit Handlers --- */
function initFormHandlers() {
  // Extraction Forms
  const usbForm = document.getElementById("form-usb-extract");
  if (usbForm) {
    usbForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const outputDir = document.getElementById("usb-out-dir").value;
      const shared = document.getElementById("usb-shared").checked;
      await submitApiRequest("/api/extract/start", { mode: "usb", output_dir: outputDir, shared: shared });
    });
  }

  const folderForm = document.getElementById("form-folder-extract");
  if (folderForm) {
    folderForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const srcPath = document.getElementById("folder-src-dir").value;
      const outputDir = document.getElementById("folder-out-dir").value;
      await submitApiRequest("/api/extract/start", { mode: "folder", src_path: srcPath, output_dir: outputDir });
    });
  }

  // Pattern Cracking
  const patForm = document.getElementById("form-pattern-crack");
  if (patForm) {
    patForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const hash = document.getElementById("pattern-hash-input").value;
      const res = await submitApiRequest("/api/crack/pattern", { hash: hash });
      if (res && res.success) {
        document.getElementById("pattern-result-box").style.display = "block";
        document.getElementById("pattern-result-text").textContent = res.pattern;
      }
    });
  }

  // PIN Cracking
  const pinForm = document.getElementById("form-pin-crack");
  if (pinForm) {
    pinForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const hash = document.getElementById("pin-hash-input").value;
      const salt = document.getElementById("pin-salt-input").value;
      const maxLen = document.getElementById("pin-len-input").value;
      const samsung = document.getElementById("pin-samsung-check").checked;
      await submitApiRequest("/api/crack/pin", { hash: hash, salt: salt, max_len: maxLen, samsung: samsung });
    });
  }

  // Tools: AB2TAR
  const abForm = document.getElementById("form-tool-ab2tar");
  if (abForm) {
    abForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const abPath = document.getElementById("tool-ab-input").value;
      await submitApiRequest("/api/tools/ab2tar", { ab_path: abPath });
    });
  }

  // Settings Save
  const cfgForm = document.getElementById("form-settings-save");
  if (cfgForm) {
    cfgForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const defPath = document.getElementById("cfg-default-path").value;
      const tz = document.getElementById("cfg-time-zone").value;
      const df = document.getElementById("cfg-date-format").value;
      const ch = document.getElementById("cfg-custom-header").value;
      await submitApiRequest("/api/config/save", { default_path: defPath, time_zone: tz, date_format: df, custom_header: ch });
    });
  }
}

async function submitApiRequest(url, payload) {
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (!data.success && data.error) {
      alert(`Error: ${data.error}`);
    }
    return data;
  } catch (err) {
    console.error("API Request failed:", err);
    alert("API Request failed. See console for details.");
  }
}
