// options.js
document.addEventListener('DOMContentLoaded', function() {
  const enableProtection = document.getElementById('enable-protection');
  const notificationThreshold = document.getElementById('notification-threshold');
  const logLevel = document.getElementById('log-level');
  const xssToggle = document.getElementById('xss-toggle');
  const xssLevel = document.getElementById('xss-level');
  const sqlToggle = document.getElementById('sql-toggle');
  const sqlLevel = document.getElementById('sql-level');
  const cmdToggle = document.getElementById('cmd-toggle');
  const cmdLevel = document.getElementById('cmd-level');
  const pathToggle = document.getElementById('path-toggle');
  const pathLevel = document.getElementById('path-level');
  const redirectToggle = document.getElementById('redirect-toggle');
  const redirectLevel = document.getElementById('redirect-level');
  const whitelistContainer = document.getElementById('whitelist-container');
  const whitelistInput = document.getElementById('whitelist-input');
  const whitelistAddBtn = document.getElementById('whitelist-add-btn');
  const saveSettings = document.getElementById('save-settings');
  const resetSettings = document.getElementById('reset-settings');
  const statusMessage = document.getElementById('status-message');
  const advancedToggle = document.getElementById('advanced-toggle');
  const advancedContent = document.getElementById('advanced-content');
  const customXssPatterns = document.getElementById('custom-xss-patterns');

  let config = {};

  function showStatus(message, isError = false) {
    statusMessage.textContent = message;
    statusMessage.className = `status-message ${isError ? 'status-error' : 'status-success'}`;
    statusMessage.style.display = 'block';
    setTimeout(() => statusMessage.style.display = 'none', 3000);
  }

  function loadConfig() {
    chrome.runtime.sendMessage({ action: 'getConfig' }, function(response) {
      if (chrome.runtime.lastError) {
        showStatus('Error loading settings', true);
        console.error('Error fetching config:', chrome.runtime.lastError);
        return;
      }
      config = response.config;
      updateUI();
    });
  }

  function updateUI() {
    enableProtection.checked = config.enabled;
    notificationThreshold.value = config.notificationThreshold;
    logLevel.value = config.logLevel;
    xssToggle.checked = config.vulnerabilities.xss.enabled;
    xssLevel.value = config.vulnerabilities.xss.level;
    sqlToggle.checked = config.vulnerabilities.sqlInjection.enabled;
    sqlLevel.value = config.vulnerabilities.sqlInjection.level;
    cmdToggle.checked = config.vulnerabilities.commandInjection.enabled;
    cmdLevel.value = config.vulnerabilities.commandInjection.level;
    pathToggle.checked = config.vulnerabilities.pathTraversal.enabled;
    pathLevel.value = config.vulnerabilities.pathTraversal.level;
    redirectToggle.checked = config.vulnerabilities.openRedirect.enabled;
    redirectLevel.value = config.vulnerabilities.openRedirect.level;

    whitelistContainer.innerHTML = '';
    config.whitelistedDomains.forEach(domain => addWhitelistItem(domain));
    customXssPatterns.value = config.customXssPatterns?.join('\n') || '';
  }

  function addWhitelistItem(domain) {
    const item = document.createElement('div');
    item.className = 'whitelist-item';
    item.innerHTML = `
      <div class="whitelist-domain">${domain}</div>
      <button class="whitelist-remove">Remove</button>
    `;
    item.querySelector('.whitelist-remove').addEventListener('click', () => {
      config.whitelistedDomains = config.whitelistedDomains.filter(d => d !== domain);
      updateUI();
    });
    whitelistContainer.appendChild(item);
  }

  function validateDomain(domain) {
    const domainRegex = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$/i;
    return domainRegex.test(domain);
  }

  whitelistAddBtn.addEventListener('click', function() {
    const domain = whitelistInput.value.trim().toLowerCase();
    if (!domain) {
      showStatus('Enter a domain', true);
      return;
    }
    if (!validateDomain(domain)) {
      showStatus('Invalid domain (e.g., use example.com)', true);
      return;
    }
    if (!config.whitelistedDomains.includes(domain)) {
      config.whitelistedDomains.push(domain);
      addWhitelistItem(domain);
      whitelistInput.value = '';
    } else {
      showStatus('Domain already whitelisted', true);
    }
  });

  let saveTimeout = null;
  saveSettings.addEventListener('click', function() {
    clearTimeout(saveTimeout);
    saveTimeout = setTimeout(() => {
      config.enabled = enableProtection.checked;
      config.notificationThreshold = notificationThreshold.value;
      config.logLevel = logLevel.value;
      config.vulnerabilities.xss.enabled = xssToggle.checked;
      config.vulnerabilities.xss.level = xssLevel.value;
      config.vulnerabilities.sqlInjection.enabled = sqlToggle.checked;
      config.vulnerabilities.sqlInjection.level = sqlLevel.value;
      config.vulnerabilities.commandInjection.enabled = cmdToggle.checked;
      config.vulnerabilities.commandInjection.level = cmdLevel.value;
      config.vulnerabilities.pathTraversal.enabled = pathToggle.checked;
      config.vulnerabilities.pathTraversal.level = pathLevel.value;
      config.vulnerabilities.openRedirect.enabled = redirectToggle.checked;
      config.vulnerabilities.openRedirect.level = redirectLevel.value;

      config.customXssPatterns = customXssPatterns.value
        .split('\n')
        .map(p => p.trim())
        .filter(p => p);

      chrome.runtime.sendMessage({ action: 'updateConfig', config }, function(response) {
        if (chrome.runtime.lastError || !response.success) {
          showStatus('Error saving settings', true);
          console.error('Error saving config:', chrome.runtime.lastError);
          return;
        }
        showStatus('Settings saved successfully');
      });
    }, 300); 
  });

  resetSettings.addEventListener('click', function() {
    if (confirm('Reset all settings to defaults?')) {
      config = {
        enabled: true,
        logLevel: 'warn',
        vulnerabilities: {
          xss: { enabled: true, level: 'medium' },
          sqlInjection: { enabled: true, level: 'medium' },
          commandInjection: { enabled: true, level: 'medium' },
          pathTraversal: { enabled: true, level: 'medium' },
          openRedirect: { enabled: true, level: 'medium' }
        },
        whitelistedDomains: [
          'google.com',
          'youtube.com',
          'facebook.com',
          'amazon.com',
          'cloudflare.com',
          'localhost'
        ],
        notificationThreshold: 'high',
        customXssPatterns: []
      };
      chrome.runtime.sendMessage({ action: 'updateConfig', config }, function(response) {
        if (chrome.runtime.lastError || !response.success) {
          showStatus('Error resetting settings', true);
          console.error('Error resetting config:', chrome.runtime.lastError);
          return;
        }
        updateUI();
        customXssPatterns.value = '';
        showStatus('Settings reset to defaults');
      });
    }
  });

  advancedToggle.addEventListener('click', function() {
    const isHidden = advancedContent.style.display === 'none' || !advancedContent.style.display;
    advancedContent.style.display = isHidden ? 'block' : 'none';
    advancedToggle.textContent = isHidden ? 'Hide Advanced Settings' : 'Show Advanced Settings';
  });

  loadConfig();
});