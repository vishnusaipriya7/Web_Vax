
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
  
  chrome.runtime.sendMessage({ action: 'getConfig' }, function(response) {
    if (response && response.config) {
      config = response.config;
    }
  });
  
  const xssPatterns = [
    /<script\b[^>]*>[\s\S]*?<\/script>/gmi,
    /javascript\s*:/gmi,
    /on\w+\s*=\s*["']?[^"'>\s]+/gmi,
    /data\s*:\s*text\/html/gmi,
    /eval\s*\(/gmi,
    /document\.cookie/gmi,
    /document\.write/gmi
  ];
  
  const xssSinks = [
    { property: 'innerHTML', riskLevel: 'high' },
    { property: 'outerHTML', riskLevel: 'high' },
    { property: 'insertAdjacentHTML', riskLevel: 'high' },
    { property: 'document.write', riskLevel: 'high' },
    { property: 'document.writeln', riskLevel: 'high' },
    { property: 'eval', riskLevel: 'high' },
    { property: 'setTimeout', riskLevel: 'medium' },
    { property: 'setInterval', riskLevel: 'medium' },
    { property: 'location', riskLevel: 'medium' },
    { property: 'src', riskLevel: 'medium' },
    { property: 'href', riskLevel: 'medium' },
    { property: 'contentWindow', riskLevel: 'medium' },
    { property: 'postMessage', riskLevel: 'medium' }
  ];
  
  function sanitizeHTML(html) {
    if (typeof html !== 'string') return html;
    
    return html
      .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gmi, '')
      .replace(/javascript\s*:/gmi, 'void:')
      .replace(/on\w+\s*=\s*["']?[^"'>\s]+/gmi, '')
      .replace(/data\s*:\s*text\/html/gmi, 'data:invalid')
      .replace(/eval\s*\(/gmi, 'void(')
      .replace(/document\.cookie/gmi, 'void(0)');
  }
  
  function detectXSS(content) {
    if (typeof content !== 'string') return false;
    
    for (const pattern of xssPatterns) {
      if (pattern.test(content)) {
        return true;
      }
    }
    
    const encodedChars = (content.match(/&#\d+;|&#x[a-f0-9]+;|%[a-f0-9]{2}/gi) || []).length;
    if (encodedChars > 5 && 
        (content.includes('<') || content.includes('>') || content.includes('script'))) {
      return true;
    }
    
    return false;
  }
  
  function detectOpenRedirect(url) {
    if (typeof url !== 'string') return false;
    
    try {
      const parsedUrl = new URL(url, window.location.href);
      
      for (const [key, value] of parsedUrl.searchParams.entries()) {
        if (/^(redirect|url|return|goto|next|target|to|link)$/i.test(key)) {
          if (/^https?:\/\//.test(value)) {
            try {
              const redirectDomain = new URL(value).hostname;
              if (redirectDomain !== window.location.hostname) {
                return true;
              }
            } catch (e) {
            }
          }
        }
      }
    } catch (e) {
    }
    
    return false;
  }
  
  function patchDOM() {
    const originalSetAttribute = Element.prototype.setAttribute;
    const originalSetProperty = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML').set;
    const originalDocumentWrite = document.write;
    const originalWindowOpen = window.open;
    const originalEval = window.eval;
    
    Element.prototype.setAttribute = function(name, value) {
      if (!config.enabled) {
        originalSetAttribute.call(this, name, value);
        return;
      }
      
      if (name.toLowerCase().startsWith('on')) {
        if (detectXSS(value)) {
          console.warn('[WebVax] Blocked potentially malicious event handler:', name);
          return; 
        }
      }
      
      if ((this.tagName === 'SCRIPT' && name === 'src') || 
          (this.tagName === 'IFRAME' && name === 'src') ||
          (name === 'href' && detectOpenRedirect(value))) {
        
        console.warn('[WebVax] Potentially unsafe attribute:', { 
          element: this.tagName, 
          attribute: name, 
          value: value 
        });
        
        if (config.vulnerabilities.xss.level === 'high' || 
            config.vulnerabilities.openRedirect.level === 'high') {
          return;
        } else {
          originalSetAttribute.call(this, name, sanitizeHTML(value));
          return;
        }
      }
      
      originalSetAttribute.call(this, name, value);
    };
    
    Object.defineProperty(Element.prototype, 'innerHTML', {
      set: function(value) {
        if (!config.enabled) {
          originalSetProperty.call(this, value);
          return;
        }
        
        if (detectXSS(value)) {
          console.warn('[WebVax] Detected potential XSS in innerHTML');
          
          if (config.vulnerabilities.xss.level === 'high') {
            originalSetProperty.call(this, '');
            chrome.runtime.sendMessage({
              action: 'threatDetected',
              type: 'xss',
              payload: value.substring(0, 100), 
              url: window.location.href
            });
          } else {
            originalSetProperty.call(this, sanitizeHTML(value));
          }
        } else {
          originalSetProperty.call(this, value);
        }
      },
      get: Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML').get,
      configurable: true
    });
    
    document.write = function() {
      if (!config.enabled) {
        return originalDocumentWrite.apply(this, arguments);
      }
      
      const content = Array.from(arguments).join('');
      
      if (detectXSS(content)) {
        console.warn('[WebVax] Blocked potential XSS in document.write');
        
        if (config.vulnerabilities.xss.level === 'high') {
          return;
        } else {
          return originalDocumentWrite.call(this, sanitizeHTML(content));
        }
      }
      
      return originalDocumentWrite.apply(this, arguments);
    };
    
    window.open = function(url, target, features) {
      if (!config.enabled) {
        return originalWindowOpen.call(this, url, target, features);
      }
      
      if (detectOpenRedirect(url)) {
        console.warn('[WebVax] Potential open redirect detected:', url);
        
        if (config.vulnerabilities.openRedirect.level === 'high') {
          return null;
        }
      }
      
      return originalWindowOpen.call(this, url, target, features);
    };
    
    window.eval = function(code) {
      if (!config.enabled) {
        return originalEval.call(this, code);
      }
      
      if (detectXSS(code)) {
        console.warn('[WebVax] Blocked potential malicious eval code');
        
        if (config.vulnerabilities.xss.level === 'high') {
          return undefined;
        }
      }
      
      return originalEval.call(this, code);
    };
  }
  
  function setupDOMObserver() {
    const observer = new MutationObserver(function(mutations) {
      if (!config.enabled) return;
      
      mutations.forEach(function(mutation) {
        if (mutation.addedNodes && mutation.addedNodes.length > 0) {
          for (let i = 0; i < mutation.addedNodes.length; i++) {
            const node = mutation.addedNodes[i];
            
            if (node.nodeType === Node.ELEMENT_NODE) {
              if (node.tagName === 'SCRIPT') {
                if (detectXSS(node.textContent) || detectXSS(node.src)) {
                  console.warn('[WebVax] Blocked potentially malicious script');
                  node.remove(); 
                }
              }
              
              if (node.tagName === 'IFRAME') {
                if (detectOpenRedirect(node.src)) {
                  console.warn('[WebVax] Blocked potentially malicious iframe source');
                  node.src = 'about:blank'; 
                }
              }
              
              if (node.tagName === 'A') {
                if (detectOpenRedirect(node.href)) {
                  console.warn('[WebVax] Detected potential redirect in link');
                  node.setAttribute('data-wvs-flagged', 'true');
                  node.style.border = '2px solid red';
                  
                  node.addEventListener('click', function(e) {
                    if (config.vulnerabilities.openRedirect.level === 'high') {
                      e.preventDefault();
                      alert('WebVax has blocked navigation to a potentially malicious URL');
                    }
                  });
                }
              }
              
              scanElement(node);
            }
          }
        }
        
        if (mutation.type === 'attributes') {
          const node = mutation.target;
          const attributeName = mutation.attributeName;
          
          if (attributeName === 'src' && (node.tagName === 'SCRIPT' || node.tagName === 'IFRAME')) {
            const attrValue = node.getAttribute(attributeName);
            if (detectXSS(attrValue)) {
              console.warn('[WebVax] Blocked potentially malicious attribute update');
              node.setAttribute(attributeName, 'about:blank');
            }
          }
          
          if (attributeName === 'href' && node.tagName === 'A') {
            const attrValue = node.getAttribute(attributeName);
            if (detectOpenRedirect(attrValue)) {
              console.warn('[WebVax] Flagged potentially dangerous link');
              node.setAttribute('data-wvs-flagged', 'true');
              node.style.border = '2px solid red';
            }
          }
        }
      });
    });
    
    observer.observe(document.documentElement || document.body, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ['src', 'href', 'onclick', 'onerror']
    });
  }
  
  function scanElement(element) {
    if (!element || element.nodeType !== Node.ELEMENT_NODE) return;
    
    if (element.attributes) {
      for (let i = 0; i < element.attributes.length; i++) {
        const attr = element.attributes[i];
        
        if (attr.name.toLowerCase().startsWith('on')) {
          if (detectXSS(attr.value)) {
            console.warn('[WebVax] Removed potentially malicious event handler:', attr.name);
            element.removeAttribute(attr.name);
          }
        }
        
        if (attr.name === 'src' || attr.name === 'href') {
          if (detectXSS(attr.value) || detectOpenRedirect(attr.value)) {
            console.warn('[WebVax] Neutralized potentially dangerous URL in', attr.name);
            if (attr.name === 'src' && (element.tagName === 'IFRAME' || element.tagName === 'FRAME')) {
              element.setAttribute(attr.name, 'about:blank');
            } else if (attr.name === 'src' && element.tagName === 'SCRIPT') {
              element.remove(); // Remove potentially harmful scripts
            } else if (attr.name === 'href' && element.tagName === 'A') {
              element.setAttribute('data-wvs-flagged', 'true');
              element.style.border = '2px solid red';
            }
          }
        }
      }
    }
    
    const children = element.children;
    if (children) {
      for (let i = 0; i < children.length; i++) {
        scanElement(children[i]);
      }
    }
  }
  
  function scanPage() {
    console.log('[WebVax] Scanning page for vulnerabilities...');
    
    const scripts = document.getElementsByTagName('script');
    for (let i = 0; i < scripts.length; i++) {
      if (detectXSS(scripts[i].innerHTML) || detectXSS(scripts[i].src)) {
        console.warn('[WebVax] Detected potentially malicious script:', scripts[i]);
        scripts[i].remove();
      }
    }
    
    const iframes = document.getElementsByTagName('iframe');
    for (let i = 0; i < iframes.length; i++) {
      if (detectOpenRedirect(iframes[i].src)) {
        console.warn('[WebVax] Detected potentially dangerous iframe source:', iframes[i].src);
        iframes[i].src = 'about:blank';
      }
    }
    
    const links = document.getElementsByTagName('a');
    for (let i = 0; i < links.length; i++) {
      if (detectOpenRedirect(links[i].href)) {
        console.warn('[WebVax] Detected potentially dangerous link:', links[i].href);
        links[i].setAttribute('data-wvs-flagged', 'true');
        links[i].style.border = '2px solid red';
      }
    }
    
    scanElement(document.body);
    
    console.log('[WebVax] Page scan complete');
  }
  
  function checkForPhishingUrls() {
    const suspiciousDomainPatterns = [
      /(paypal|apple|microsoft|google|facebook|amazon|netflix).*\.(tk|ml|ga|cf|gq|xyz)/i,
      /bank.*\.(info|top|xyz|club)/i,
      /secure.*\.(date|racing|win|loan)/i
    ];
    
    const links = document.getElementsByTagName('a');
    for (let i = 0; i < links.length; i++) {
      try {
        const url = new URL(links[i].href);
        const domain = url.hostname;
        
        for (const pattern of suspiciousDomainPatterns) {
          if (pattern.test(domain)) {
            console.warn('[WebVax] Detected potentially phishing link:', links[i].href);
            links[i].style.backgroundColor = '#ffdddd';
            links[i].style.border = '2px dashed red';
            links[i].setAttribute('data-wvs-phishing', 'true');
            
            links[i].title = 'WARNING: This link may be a phishing attempt!';
            
            links[i].addEventListener('click', function(e) {
              if (confirm('This link appears to be suspicious and may be a phishing attempt. Do you still want to proceed?') === false) {
                e.preventDefault();
              }
            });
          }
        }
      } catch (e) {
      }
    }
  }
  
  chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
    if (request.action === 'vulnerabilityDetected') {
      console.warn('[WebVax] Vulnerability detected by background script:', request.vulnerabilities);
      
      if (request.vulnerabilities.some(v => v.severity === 'high')) {
        setTimeout(function() {
          showNotification('High severity vulnerability detected in this page!');
        }
        , 5000);
       
      }
    } else if (request.action === 'scanPage') {
      scanPage();
      sendResponse({ success: true });
    } else if (request.action === 'updateConfig') {
      config = request.config;
      sendResponse({ success: true });
    }
  });
  
  function showNotification(message) {
    const notification = document.createElement('div');
    notification.style.position = 'fixed';
    notification.style.top = '10px';
    notification.style.right = '10px';
    notification.style.backgroundColor = '#ff4d4d';
    notification.style.color = 'white';
    notification.style.padding = '10px';
    notification.style.borderRadius = '5px';
    notification.style.zIndex = '9999';
    notification.style.boxShadow = '0 2px 10px rgba(0,0,0,0.2)';
  notification.style.fontFamily = 'Arial, sans-serif';
  notification.style.fontSize = '14px';
  notification.textContent = message;
  
  const closeButton = document.createElement('span');
  closeButton.textContent = '×';
  closeButton.style.marginLeft = '10px';
  closeButton.style.cursor = 'pointer';
  closeButton.style.fontWeight = 'bold';
  closeButton.style.fontSize = '18px';
  closeButton.addEventListener('click', function() {
    notification.remove();
  });
  notification.appendChild(closeButton);
  
  document.body.appendChild(notification);
  
  setTimeout(function() {
    if (notification.parentNode) {
      notification.remove();
    }
  }, 5000);
}

function injectCSSSecurity() {
  const style = document.createElement('style');
  style.textContent = `
    
    object[data*="javascript:"],
    embed[src*="javascript:"],
    object[data*="data:"],
    embed[src*="data:"] {
      display: none !important;
    }
    
   
    [data-wvs-flagged="true"] {
      position: relative;
    }
    
    [data-wvs-flagged="true"]::before {
      content: "⚠️";
      position: absolute;
      top: -15px;
      left: 0;
      background-color: red;
      color: white;
      padding: 2px 5px;
      border-radius: 3px;
      font-size: 10px;
      white-space: nowrap;
    }
    
   
    form:not([action^="https://${window.location.hostname}/"]):not([action^="http://${window.location.hostname}/"]):not([action^="/"]):not([action^="."]):not([action=""]) {
      border: 2px solid red;
    }
  `;
  
  (document.head || document.documentElement).appendChild(style);
}

function interceptFormSubmissions() {
  document.addEventListener('submit', function(e) {
    if (!config.enabled) return;
    
    const form = e.target;
    
    if (form.action && detectOpenRedirect(form.action)) {
      console.warn('[WebVax] Potentially dangerous form submission destination:', form.action);
      
      if (config.vulnerabilities.openRedirect.level === 'high') {
        e.preventDefault();
       setTimeout(function() {
          showNotification('Blocked form submission to a potentially dangerous URL');
        }
        , 5000);
      }
    }
    
    let hasVulnerability = false;
    const formInputs = form.querySelectorAll('input, textarea');
    
    for (let i = 0; i < formInputs.length; i++) {
      const input = formInputs[i];
      
      if (input.value && (detectXSS(input.value) || 
                        detectionEngines.sqlInjection?.detect(input.value)?.detected || 
                        detectionEngines.commandInjection?.detect(input.value)?.detected)) {
        console.warn('[WebVax] Potentially malicious data in form input:', input.name);
        hasVulnerability = true;
        
        input.style.border = '2px solid red';
        input.style.backgroundColor = '#ffeeee';
      }
    }
    
    if (hasVulnerability && config.vulnerabilities.xss.level === 'high') {
      e.preventDefault();
      setTimeout(function() {
        showNotification('Blocked form submission containing potentially malicious data');
      }
      , 5000);
    }
  }, true);
}

function monitorFileUploads() {
  document.addEventListener('change', function(e) {
    if (!config.enabled) return;
    
    const input = e.target;
    
    if (input.type === 'file') {
      const files = input.files;
      
      if (files.length > 0) {
        for (let i = 0; i < files.length; i++) {
          const file = files[i];
          const extension = file.name.split('.').pop().toLowerCase();
          
          const dangerousExtensions = ['exe', 'dll', 'bat', 'cmd', 'vbs', 'js', 'jse', 'php', 'phtml', 'asp', 'aspx', 'jsp'];
          
          if (dangerousExtensions.includes(extension)) {
            console.warn('[WebVax] Potentially dangerous file upload detected:', file.name);
            
           
            setTimeout(function() {
              showNotification(`Warning: You're uploading a potentially dangerous file type (${extension})`);
            }
            , 5000);
            
            input.style.border = '2px solid orange';
            input.style.backgroundColor = '#fffaee';
          }
        }
      }
    }
  }, true);
}

(function() {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initialize);
  } else {
    initialize();
  }
  
  function initialize() {
    console.log('[WebVax] Initializing content protection...');
    
    loadDetectionEngines();
    
    patchDOM();
    
    setupDOMObserver();
    
    injectCSSSecurity();
    
    interceptFormSubmissions();
    
    monitorFileUploads();
    
    checkForPhishingUrls();
    
    scanPage();
    
    console.log('[WebVax] Content protection initialized');
  }
  
  function loadDetectionEngines() {

    detectionEngines = {
      sqlInjection: {
        detect: function(input) {
          if (typeof input !== 'string') return { detected: false };
          
          const sqlPatterns = [
            /\b(union|select|insert|update|delete|drop|alter)\b\s+/gi,
            /'\s*(or|and)\s*['"]?\s*[0-9a-zA-Z]+['"]?\s*[=<>]/gi,
            /'\s*;\s*[a-zA-Z]+/gi
          ];
          
          for (const pattern of sqlPatterns) {
            if (pattern.test(input)) {
              return { detected: true, pattern: pattern.toString() };
            }
          }
          
          return { detected: false };
        }
      },
      
      commandInjection: {
        detect: function(input) {
          if (typeof input !== 'string') return { detected: false };
          
          const commandPatterns = [
            /[&|;`$><]/g,
            /\b(ping|telnet|nslookup|traceroute|dig|wget|curl|nc|netcat)\b/gi,
            /\|\s*\w+/gi,
            /`.*`/g
          ];
          
          for (const pattern of commandPatterns) {
            if (pattern.test(input)) {
              return { detected: true, pattern: pattern.toString() };
            }
          }
          
          return { detected: false };
        }
      }
    };
  }
})();