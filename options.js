
const enableProtectionToggle = document.getElementById('enable-protection');
const notificationThresholdSelect = document.getElementById('notification-threshold');
const logLevelSelect = document.getElementById('log-level');

const xssToggle = document.getElementById('xss-toggle');
const xssLevelSelect = document.getElementById('xss-level');
const sqlToggle = document.getElementById('sql-toggle');
const sqlLevelSelect = document.getElementById('sql-level');
const cmdToggle = document.getElementById('cmd-toggle');
const cmdLevelSelect = document.getElementById('cmd-level');
const pathToggle = document.getElementById('path-toggle');
const pathLevelSelect = document.getElementById('path-level');
const redirectToggle = document.getElementById('redirect-toggle');
const redirectLevelSelect = document.getElementById('redirect-level');

const whitelistContainer = document.getElementById('whitelist-container');
const whitelistInput = document.getElementById('whitelist-input');
const whitelistAddBtn = document.getElementById('whitelist-add-btn');

const advancedToggle = document.getElementById('advanced-toggle');
const advancedContent = document.getElementById('advanced-content');
const domObserverToggle = document.getElementById('dom-observer-toggle');
const formProtectionToggle = document.getElementById('form-protection-toggle');
const cssProtectionToggle = document.getElementById('css-protection-toggle');
const fileUploadToggle = document.getElementById('file-upload-toggle');

const resetDefaultsBtn = document.getElementById('reset-defaults');
const saveSettingsBtn = document.getElementById('save-settings');
const statusMessage = document.getElementById('status-message');

let config = {
  enabled: true,
  logLevel: 'info',
  notificationThreshold: 'medium',
  vulnerabilities: {
    xss: { enabled: true, level: 'high' },
    sqlInjection: { enabled: true, level: 'high' },
    commandInjection: { enabled: true, level: 'high' },
    pathTraversal: { enabled: true, level: 'high' },
    openRedirect: { enabled: true, level: 'high' }
  },
  whitelistedDomains: [],
  advanced: {
    domObserver: true,
    formProtection: true,
    cssProtection: true,
    fileUploadMonitoring: true
  }
};

document.addEventListener('DOMContentLoaded', function() {
  loadSettings();
  
  setupEventListeners();
});

function loadSettings() {
  chrome.storage.local.get('securityConfig', function(result) {
    if (result.securityConfig) {
      config = result.securityConfig;
    }
    
    updateUI();
  });
}

function updateUI() {
  enableProtectionToggle.checked = config.enabled;
  notificationThresholdSelect.value = config.notificationThreshold || 'medium';
  logLevelSelect.value = config.logLevel || 'info';
  
  xssToggle.checked = config.vulnerabilities.xss.enabled;
  xssLevelSelect.value = config.vulnerabilities.xss.level;
  sqlToggle.checked = config.vulnerabilities.sqlInjection.enabled;
  sqlLevelSelect.value = config.vulnerabilities.sqlInjection.level;
  cmdToggle.checked = config.vulnerabilities.commandInjection.enabled;
  cmdLevelSelect.value = config.vulnerabilities.commandInjection.level;
  pathToggle.checked = config.vulnerabilities.pathTraversal.enabled;
  pathLevelSelect.value = config.vulnerabilities.pathTraversal.level;
  redirectToggle.checked = config.vulnerabilities.openRedirect.enabled;
  redirectLevelSelect.value = config.vulnerabilities.openRedirect.level;
  
  updateWhitelistUI();
  
  domObserverToggle.checked = config.advanced?.domObserver !== false;
  formProtectionToggle.checked = config.advanced?.formProtection !== false;
  cssProtectionToggle.checked = config.advanced?.cssProtection !== false;
  fileUploadToggle.checked = config.advanced?.fileUploadMonitoring !== false;
}

function updateWhitelistUI() {
  whitelistContainer.innerHTML = '';
  
  if (!config.whitelistedDomains || config.whitelistedDomains.length === 0) {
    const emptyMessage = document.createElement('div');
    emptyMessage.className = 'whitelist-item';
    emptyMessage.textContent = 'No domains whitelisted. All websites will be scanned.';
    whitelistContainer.appendChild(emptyMessage);
    return;
  }
  
  config.whitelistedDomains.forEach(function(domain, index) {
    const item = document.createElement('div');
    item.className = 'whitelist-item';
    
    const domainText = document.createElement('div');
    domainText.className = 'whitelist-domain';
    domainText.textContent = domain;
    item.appendChild(domainText);
    
    const removeButton = document.createElement('button');
    removeButton.className = 'whitelist-remove';
    removeButton.textContent = 'Remove';
    removeButton.dataset.index = index;
    removeButton.addEventListener('click', function() {
      removeWhitelistDomain(index);
    });
    item.appendChild(removeButton);
    
    whitelistContainer.appendChild(item);
  });
}

function addWhitelistDomain(domain) {
  if (!domain) return false;
  
  let cleanDomain = domain.trim().toLowerCase();
  cleanDomain = cleanDomain.replace(/^https?:\/\//i, '');
  cleanDomain = cleanDomain.replace(/^www\./i, '');
  
  cleanDomain = cleanDomain.split('/')[0];
  
  if (config.whitelistedDomains.includes(cleanDomain)) {
    showStatusMessage('Domain already in whitelist', 'error');
    return false;
  }
  
  config.whitelistedDomains.push(cleanDomain);
  
  updateWhitelistUI();
  
  whitelistInput.value = '';
  
  return true;
}

function removeWhitelistDomain(index) {
  if (index >= 0 && index < config.whitelistedDomains.length) {
    config.whitelistedDomains.splice(index, 1);
    updateWhitelistUI();
  }
}

function saveSettings() {
  config.enabled = enableProtectionToggle.checked;
  config.notificationThreshold = notificationThresholdSelect.value;
  config.logLevel = logLevelSelect.value;
  
  config.vulnerabilities.xss.enabled = xssToggle.checked;
  config.vulnerabilities.xss.level = xssLevelSelect.value;
  config.vulnerabilities.sqlInjection.enabled = sqlToggle.checked;
  config.vulnerabilities.sqlInjection.level = sqlLevelSelect.value;
  config.vulnerabilities.commandInjection.enabled = cmdToggle.checked;
  config.vulnerabilities.commandInjection.level = cmdLevelSelect.value;
  config.vulnerabilities.pathTraversal.enabled = pathToggle.checked;
  config.vulnerabilities.pathTraversal.level = pathLevelSelect.value;
  config.vulnerabilities.openRedirect.enabled = redirectToggle.checked;
  config.vulnerabilities.openRedirect.level = redirectLevelSelect.value;
  
  if (!config.advanced) config.advanced = {};
  config.advanced.domObserver = domObserverToggle.checked;
  config.advanced.formProtection = formProtectionToggle.checked;
  config.advanced.cssProtection = cssProtectionToggle.checked;
  config.advanced.fileUploadMonitoring = fileUploadToggle.checked;
  
  chrome.storage.local.set({ securityConfig: config }, function() {
    showStatusMessage('Settings saved successfully!', 'success');
    
    chrome.runtime.sendMessage({ 
      action: 'updateConfig', 
      config: config 
    });
    
    chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
      if (tabs[0]) {
        chrome.tabs.sendMessage(tabs[0].id, { 
          action: 'updateConfig', 
          config: config 
        });
      }
    });
  });
}

function resetToDefaults() {
  const defaultConfig = {
    enabled: true,
    logLevel: 'info',
    notificationThreshold: 'medium',
    vulnerabilities: {
      xss: { enabled: true, level: 'high' },
      sqlInjection: { enabled: true, level: 'high' },
      commandInjection: { enabled: true, level: 'high' },
      pathTraversal: { enabled: true, level: 'high' },
      openRedirect: { enabled: true, level: 'high' }
    },
    whitelistedDomains: [],
    advanced: {
      domObserver: true,
      formProtection: true,
      cssProtection: true,
      fileUploadMonitoring: true
    }
  };
  
  config = defaultConfig;
  
  updateUI();
  
  showStatusMessage('Settings reset to defaults', 'success');
}

function showStatusMessage(message, type) {
  statusMessage.textContent = message;
  statusMessage.className = 'status-message status-' + type;
  statusMessage.style.display = 'block';
  
  setTimeout(function() {
    statusMessage.style.display = 'none';
  }, 3000);
}

function setupEventListeners() {
  xssToggle.addEventListener('change', function() {
    xssLevelSelect.disabled = !this.checked;
  });
  
  sqlToggle.addEventListener('change', function() {
    sqlLevelSelect.disabled = !this.checked;
  });
  
  cmdToggle.addEventListener('change', function() {
    cmdLevelSelect.disabled = !this.checked;
  });
  
  pathToggle.addEventListener('change', function() {
    pathLevelSelect.disabled = !this.checked;
  });
  
  redirectToggle.addEventListener('change', function() {
    redirectLevelSelect.disabled = !this.checked;
  });
  
  whitelistAddBtn.addEventListener('click', function() {
    const domain = whitelistInput.value.trim();
    if (domain) {
      addWhitelistDomain(domain);
    } else {
      showStatusMessage('Please enter a valid domain', 'error');
    }
  });
  
  whitelistInput.addEventListener('keypress', function(e) {
    if (e.key === 'Enter') {
      const domain = whitelistInput.value.trim();
      if (domain) {
        addWhitelistDomain(domain);
      } else {
        showStatusMessage('Please enter a valid domain', 'error');
      }
    }
  });
  
  advancedToggle.addEventListener('click', function() {
    const isVisible = advancedContent.style.display === 'block';
    advancedContent.style.display = isVisible ? 'none' : 'block';
    this.textContent = isVisible ? '▶ Show Advanced Settings' : '▼ Hide Advanced Settings';
  });
  
  saveSettingsBtn.addEventListener('click', function() {
    saveSettings();
  });
  
  resetDefaultsBtn.addEventListener('click', function() {
    if (confirm('Are you sure you want to reset all settings to defaults?')) {
      resetToDefaults();
    }
  });
}