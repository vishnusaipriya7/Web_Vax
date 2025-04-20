
const protectionToggle = document.getElementById('protection-toggle');
const totalThreatsEl = document.getElementById('total-threats');
const xssThreatsEl = document.getElementById('xss-threats');
const sqlThreatsEl = document.getElementById('sql-threats');
const cmdThreatsEl = document.getElementById('cmd-threats');
const pathThreatsEl = document.getElementById('path-threats');
const redirectThreatsEl = document.getElementById('redirect-threats');
const threatListEl = document.getElementById('threat-list');
const scanPageBtn = document.getElementById('scan-page');
const resetStatsBtn = document.getElementById('reset-stats');
const openSettingsBtn = document.getElementById('open-settings');

let config = {
  enabled: true,
  vulnerabilities: {
    xss: { enabled: true, level: 'high' },
    sqlInjection: { enabled: true, level: 'high' },
    commandInjection: { enabled: true, level: 'high' },
    pathTraversal: { enabled: true, level: 'high' },
    openRedirect: { enabled: true, level: 'high' }
  }
};

let threatStats = {
  totalThreatsDetected: 0,
  threatsByType: {
    xss: 0,
    sqlInjection: 0,
    commandInjection: 0,
    pathTraversal: 0,
    openRedirect: 0
  },
  recentThreats: []
};

document.addEventListener('DOMContentLoaded', function() {
  loadConfigAndStats();
  
  setupEventListeners();
});

function loadConfigAndStats() {
  chrome.runtime.sendMessage({ action: 'getConfig' }, function(response) {
    if (response && response.config) {
      config = response.config;
      updateToggleUI();
    }
  });
  
  chrome.runtime.sendMessage({ action: 'getThreatStats' }, function(response) {
    if (response && response.threatStats) {
      threatStats = response.threatStats;
      updateStatsUI();
    }
  });
}

function updateToggleUI() {
  protectionToggle.checked = config.enabled;
}

function updateStatsUI() {
  totalThreatsEl.textContent = threatStats.totalThreatsDetected;
  xssThreatsEl.textContent = threatStats.threatsByType.xss || 0;
  sqlThreatsEl.textContent = threatStats.threatsByType.sqlInjection || 0;
  cmdThreatsEl.textContent = threatStats.threatsByType.commandInjection || 0;
  pathThreatsEl.textContent = threatStats.threatsByType.pathTraversal || 0;
  redirectThreatsEl.textContent = threatStats.threatsByType.openRedirect || 0;
  
  updateThreatList();
}

function updateThreatList() {
  threatListEl.innerHTML = '';
  
  if (!threatStats.recentThreats || threatStats.recentThreats.length === 0) {
    const noThreatsEl = document.createElement('div');
    noThreatsEl.className = 'threat-item';
    noThreatsEl.textContent = 'No threats detected yet';
    threatListEl.appendChild(noThreatsEl);
    return;
  }
  
  const threats = threatStats.recentThreats.slice(0, 10);
  
  threats.forEach(function(threat) {
    const threatEl = document.createElement('div');
    threatEl.className = `threat-item threat-severity-${threat.severity}`;
    
    const typeEl = document.createElement('div');
    typeEl.className = 'threat-type';
    typeEl.textContent = formatThreatType(threat.type);
    threatEl.appendChild(typeEl);
    
    const urlEl = document.createElement('div');
    urlEl.className = 'threat-url tooltip';
    urlEl.textContent = formatUrl(threat.url);
    
    if (threat.payload) {
      const tooltipEl = document.createElement('span');
      tooltipEl.className = 'tooltip-text';
      tooltipEl.textContent = `Payload: ${truncateString(threat.payload, 50)}`;
      urlEl.appendChild(tooltipEl);
    }
    
    threatEl.appendChild(urlEl);
    
    const timeEl = document.createElement('div');
    timeEl.className = 'threat-time';
    timeEl.textContent = formatTimestamp(threat.timestamp);
    threatEl.appendChild(timeEl);
    
    threatListEl.appendChild(threatEl);
  });
}

function formatUrl(url) {
  if (!url) return 'Unknown URL';
  
  try {
    const urlObj = new URL(url);
    return `${urlObj.hostname}${urlObj.pathname.substring(0, 20)}${urlObj.pathname.length > 20 ? '...' : ''}`;
  } catch (e) {
    return truncateString(url, 30);
  }
}

function formatTimestamp(timestamp) {
  if (!timestamp) return '';
  
  try {
    const date = new Date(timestamp);
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  } catch (e) {
    return '';
  }
}

function formatThreatType(type) {
  if (!type) return 'Unknown';
  
  const typeMap = {
    'xss': 'XSS Attack',
    'sqlInjection': 'SQL Injection',
    'commandInjection': 'Command Injection',
    'pathTraversal': 'Path Traversal',
    'openRedirect': 'Open Redirect'
  };
  
  return typeMap[type] || type;
}

function truncateString(str, maxLength) {
  if (!str) return '';
  if (str.length <= maxLength) return str;
  return str.substring(0, maxLength) + '...';
}

function setupEventListeners() {
  protectionToggle.addEventListener('change', function() {
    const enabled = protectionToggle.checked;
    
    config.enabled = enabled;
    
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
  
  scanPageBtn.addEventListener('click', function() {
    scanPageBtn.textContent = 'Scanning...';
    scanPageBtn.disabled = true;
    
    chrome.runtime.sendMessage({ action: 'scanPage' }, function(response) {
      setTimeout(function() {
        scanPageBtn.textContent = 'Scan Page';
        scanPageBtn.disabled = false;
      }, 1000);
    });
  });
  
  resetStatsBtn.addEventListener('click', function() {
    chrome.runtime.sendMessage({ action: 'resetThreatStats' }, function(response) {
      if (response && response.success) {
        loadConfigAndStats();
      }
    });
  });
  
  openSettingsBtn.addEventListener('click', function() {
    chrome.runtime.openOptionsPage();
  });
}

chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
  if (request.action === 'threatStatsUpdated') {
    loadConfigAndStats();
  }
});