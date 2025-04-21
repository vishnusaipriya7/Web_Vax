document.addEventListener('DOMContentLoaded', function() {
  const protectionToggle = document.getElementById('protection-toggle');
  const totalThreats = document.getElementById('total-threats');
  const xssThreats = document.getElementById('xss-threats');
  const sqlThreats = document.getElementById('sql-threats');
  const cmdThreats = document.getElementById('cmd-threats');
  const pathThreats = document.getElementById('path-threats');
  const redirectThreats = document.getElementById('redirect-threats');
  const threatList = document.getElementById('threat-list');
  const scanPageButton = document.getElementById('scan-page');
  const resetStatsButton = document.getElementById('reset-stats');
  const openSettingsButton = document.getElementById('open-settings');

  function updateUI(config, stats) {
    protectionToggle.checked = config.enabled || false;
    totalThreats.textContent = stats.totalThreatsDetected || 0;
    xssThreats.textContent = stats.threatsByType?.xss || 0;
    sqlThreats.textContent = stats.threatsByType?.sqlInjection || 0;
    cmdThreats.textContent = stats.threatsByType?.commandInjection || 0;
    pathThreats.textContent = stats.threatsByType?.pathTraversal || 0;
    redirectThreats.textContent = stats.threatsByType?.openRedirect || 0;

    threatList.innerHTML = '';
    (stats.recentThreats || [])
      .slice(0, 5)
      .forEach(threat => {
        const threatItem = document.createElement('div');
        threatItem.className = `threat-item threat-severity-${threat.severity}`;
        threatItem.innerHTML = `
          <div class="threat-type">${threat.type} (Blocked)</div>
          <div class="threat-url">${truncateUrl(threat.url)}</div>
          <div class="threat-time">${formatTime(threat.timestamp)}</div>
        `;
        threatList.appendChild(threatItem);
      });
  }

  function truncateUrl(url, maxLength = 30) {
    try {
      const parsedUrl = new URL(url);
      const path = parsedUrl.pathname + parsedUrl.search;
      return path.length > maxLength ? path.substring(0, maxLength - 3) + '...' : path;
    } catch (e) {
      return url.length > maxLength ? url.substring(0, maxLength - 3) + '...' : url;
    }
  }

  function formatTime(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }

  function loadData() {
    chrome.runtime.sendMessage({ action: 'getConfig' }, function(configResponse) {
      if (chrome.runtime.lastError) {
        console.error('Error fetching config:', chrome.runtime.lastError);
        updateUI({}, {});
        return;
      }
      chrome.runtime.sendMessage({ action: 'getThreatStats' }, function(statsResponse) {
        if (chrome.runtime.lastError) {
          console.error('Error fetching stats:', chrome.runtime.lastError);
          updateUI(configResponse.config, {});
          return;
        }
        updateUI(configResponse.config, statsResponse.threatStats);
      });
    });
  }

  protectionToggle.addEventListener('change', function() {
    chrome.runtime.sendMessage({
      action: 'updateConfig',
      config: { enabled: protectionToggle.checked }
    }, function(response) {
      if (chrome.runtime.lastError || !response.success) {
        console.error('Error updating config:', chrome.runtime.lastError);
        protectionToggle.checked = !protectionToggle.checked;
        return;
      }
      loadData();
    });
  });

  scanPageButton.addEventListener('click', function() {
    chrome.runtime.sendMessage({ action: 'scanPage' }, function(response) {
      if (chrome.runtime.lastError || !response.success) {
        console.error('Error initiating scan:', chrome.runtime.lastError);
        return;
      }
      scanPageButton.textContent = 'Scanning...';
      setTimeout(() => scanPageButton.textContent = 'Scan Page', 2000);
    });
  });

  resetStatsButton.addEventListener('click', function() {
    if (confirm('Reset all threat statistics?')) {
      chrome.runtime.sendMessage({ action: 'resetThreatStats' }, function(response) {
        if (chrome.runtime.lastError || !response.success) {
          console.error('Error resetting stats:', chrome.runtime.lastError);
          return;
        }
        loadData();
      });
    }
  });

  openSettingsButton.addEventListener('click', function() {
    chrome.runtime.openOptionsPage();
  });

  // Listen for real-time threat updates
  chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
    if (request.action === 'threatUpdate') {
      chrome.runtime.sendMessage({ action: 'getConfig' }, function(configResponse) {
        if (chrome.runtime.lastError) {
          console.error('Error fetching config:', chrome.runtime.lastError);
          return;
        }
        updateUI(configResponse.config, request.threatStats);
      });
    }
  });

  loadData();
});