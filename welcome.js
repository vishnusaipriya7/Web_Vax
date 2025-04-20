
document.addEventListener('DOMContentLoaded', function() {
    const openSettingsBtn = document.getElementById('open-settings');
    if (openSettingsBtn) {
      openSettingsBtn.addEventListener('click', function() {
        chrome.runtime.openOptionsPage();
      });
    }
    
    const privacyLink = document.getElementById('privacy-link');
    if (privacyLink) {
      privacyLink.addEventListener('click', function(e) {
        e.preventDefault();
        alert('Privacy Policy: This extension does not collect or transmit any personal data. All scanning and protection is performed locally in your browser.');
      });
    }
    
    const termsLink = document.getElementById('terms-link');
    if (termsLink) {
      termsLink.addEventListener('click', function(e) {
        e.preventDefault();
        alert('Terms of Use: This extension is provided "as is" without warranty of any kind. Use at your own risk. The developers are not liable for any damages arising from the use of this extension.');
      });
    }
    
    chrome.runtime.sendMessage({ action: 'getInstallType' }, function(response) {
      if (response && response.installType === 'update') {
        showWhatsNew();
      }
    });
    
    function showWhatsNew() {
      const container = document.querySelector('.container');
      
      const section = document.createElement('div');
      section.className = 'section';
      section.innerHTML = `
        <h2>What's New in This Version</h2>
        <p>Thank you for updating WebVax! Here are the latest improvements:</p>
        
        <ul>
          <li>Enhanced XSS detection engine with improved pattern matching</li>
          <li>Added protection against DOM-based vulnerabilities</li>
          <li>Improved performance and reduced browser resource usage</li>
          <li>New whitelist feature for trusted domains</li>
          <li>Better notification system for detected threats</li>
        </ul>
      `;
      
      if (container.querySelector('.section')) {
        container.insertBefore(section, container.querySelector('.section').nextSibling);
      } else {
        container.appendChild(section);
      }
    }
  });