// SecretRadar - Popup Settings

import { debugLog, showNotification } from './ui.js';
import { loadDenyList } from './denylist.js';
import { loadCurrentTabFindings } from './findings.js';

// Initialize extension settings
export async function initializeSettings() {
  const defaults = {
    enableNotifications: true,
    confidenceThreshold: 0.3,
    autoScan: true,
    scanExternalScripts: true,
    scanSourceMaps: true,
    scanSensitiveFiles: false,
    denyList: ['https://www.google.com', '*.google.com'],
    dataRetentionDays: 7, // Default 7 days
    showAdvancedSettings: false,
    debugMode: false,
    verboseScanning: false
  };

  const storage = await chrome.storage.local.get(Object.keys(defaults));

  // Set defaults for missing settings
  for (const [key, value] of Object.entries(defaults)) {
    if (storage[key] === undefined) {
      await chrome.storage.local.set({ [key]: value });
    }
  }

  // Load deny list
  await loadDenyList();
}

// Update UI based on current settings
export async function updateUI() {
  const storage = await chrome.storage.local.get([
    'enableNotifications', 'autoScan', 'scanExternalScripts',
    'scanSourceMaps', 'scanSensitiveFiles', 'confidenceThreshold', 'dataRetentionDays',
    'showAdvancedSettings', 'debugMode', 'verboseScanning'
  ]);

  // Update toggles
  Object.entries(storage).forEach(([key, value]) => {
    const element = document.getElementById(key);
    if (element && typeof value === 'boolean') {
      element.checked = value;
    }
  });

  // Update confidence slider
  const confidenceSlider = document.getElementById('confidenceThreshold');
  const confidenceValue = document.getElementById('confidenceValue');
  if (confidenceSlider && confidenceValue) {
    confidenceSlider.value = storage.confidenceThreshold || 0.3;
    confidenceValue.textContent = `${Math.round((storage.confidenceThreshold || 0.3) * 100)}%`;
  }

  // Update retention slider
  const retentionSlider = document.getElementById('dataRetentionDays');
  const retentionValue = document.getElementById('retentionValue');
  if (retentionSlider && retentionValue) {
    retentionSlider.value = storage.dataRetentionDays || 7;
    retentionValue.textContent = `${storage.dataRetentionDays || 7} days`;
  }

  // Update advanced settings visibility
  const advancedSection = document.getElementById('advancedSettings');
  const advancedButton = document.getElementById('openSettings');
  if (advancedSection && advancedButton) {
    advancedSection.style.display = (storage.showAdvancedSettings ? 'block' : 'none');
    advancedButton.textContent = storage.showAdvancedSettings ? 'Hide Advanced' : 'Advanced';
  }

}

// Reset settings to defaults
export async function resetSettings() {
  try {
    const defaults = {
      enableNotifications: true,
      confidenceThreshold: 0.3,
      autoScan: true,
      scanExternalScripts: true,
      scanSourceMaps: true,
      scanSensitiveFiles: false,
      dataRetentionDays: 7,
      showAdvancedSettings: false,
      debugMode: false,
      verboseScanning: false
    };
    await chrome.storage.local.set(defaults);
    await updateUI();
    showNotification('Settings reset to defaults', 'success');
  } catch (error) {
    await debugLog('Error resetting settings:', error);
    showNotification('Failed to reset settings', 'error');
  }
}

// Toggle advanced settings
export async function toggleAdvancedSettings() {
  try {
    const storage = await chrome.storage.local.get(['showAdvancedSettings']);
    const newState = !storage.showAdvancedSettings;

    await chrome.storage.local.set({ showAdvancedSettings: newState });

    // Show/hide advanced settings section
    const advancedSection = document.getElementById('advancedSettings');
    if (advancedSection) {
      advancedSection.style.display = newState ? 'block' : 'none';
    }

    // Update button text
    const button = document.getElementById('openSettings');
    if (button) {
      button.textContent = newState ? 'Hide Advanced' : 'Advanced';
    }
  } catch (error) {
    await debugLog('Error toggling advanced settings:', error);
  }
}

