import { isWorking } from "./lib/status.js";

const btn = document.getElementById("status-btn");
btn.textContent = isWorking() ? "Working ✅" : "Broken ❌";
