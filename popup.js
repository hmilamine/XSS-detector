// Toggle disable state
document.getElementById('disableBtn').addEventListener('click', async () => {
  const isDisabled = await chrome.storage.local.get('isDisabled');
  const newState = !isDisabled?.isDisabled;
  
  await chrome.storage.local.set({ isDisabled: newState });
  updateButtonState(newState);
});

// Open history
document.getElementById('historyBtn').addEventListener('click', () => {
  chrome.runtime.sendMessage({ action: "openHistory" });
});

// Initial state
chrome.storage.local.get('isDisabled', (data) => {
  updateButtonState(data.isDisabled || false);
});

function updateButtonState(isDisabled) {
  const btn = document.getElementById('disableBtn');
  btn.textContent = isDisabled ? "Enable" : "Disable";
  btn.style.backgroundColor = isDisabled ? "#cccccc" : "#ff4444";
}