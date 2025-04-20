
(function() {
    window.WebVulnerabilityShield = window.WebVulnerabilityShield || {};
    
    const WVS = window.WebVulnerabilityShield;
    

    WVS.sanitizeHTML = function(html) {
      if (typeof html !== 'string') return '';
      
      const template = document.createElement('template');
      template.innerHTML = html;
      const fragment = template.content;
      
      const dangerousElements = fragment.querySelectorAll('script, object, embed, base, iframe, form');
      dangerousElements.forEach(function(element) {
        element.remove();
      });
      
      const allElements = fragment.querySelectorAll('*');
      allElements.forEach(function(element) {
        Array.from(element.attributes).forEach(function(attr) {
          if (attr.name.startsWith('on') || 
              attr.value.includes('javascript:') || 
              attr.value.includes('data:') ||
              attr.value.includes('vbscript:')) {
            element.removeAttribute(attr.name);
          }
        });
        
        if (element.hasAttribute('style')) {
          const style = element.getAttribute('style');
          if (style.includes('expression') || 
              style.includes('behavior') || 
              style.includes('url(')) {
            element.setAttribute('style', style.replace(/expression\s*\(.*?\)|behavior\s*:.*?;|url\s*\(.*?\)/gi, ''));
          }
        }
        
        if (element.hasAttribute('href')) {
          const href = element.getAttribute('href');
          if (href.includes('javascript:') || href.includes('data:')) {
            element.setAttribute('href', '#');
          }
        }
        
        if (element.hasAttribute('src')) {
          const src = element.getAttribute('src');
          if (src.includes('javascript:') || 
              (src.includes('data:') && !src.includes('data:image/'))) {
            element.removeAttribute('src');
          }
        }
      });
      
      return fragment.firstChild ? fragment.firstChild.outerHTML : '';
    };
    

    WVS.sanitizeSQLString = function(input) {
      if (typeof input !== 'string') return '';
      
      return input
      .replace(/'/g, "''")
      .replace(/;/g, "")
      .replace(/--/g, "")
      .replace(/\/\*/g, "")
      .replace(/\*\//g, "")
      .replace(/xp_/gi, "")
      .replace(/sp_/gi, "")
      .replace(/exec\s+/gi, "")
      .replace(/union\s+select/gi, "")
      .replace(/select\s+.*\s+from/gi, "select from")
      .replace(/insert\s+into/gi, "")
      .replace(/update\s+.+\s+set/gi, "")
      .replace(/delete\s+from/gi, "")
      .replace(/drop\s+table/gi, "")
      .replace(/alter\s+table/gi, "");
  };
  
  WVS.sanitizeCommand = function(input) {
    if (typeof input !== 'string') return '';
    
    return input
      .replace(/[&|;`$><]/g, '')
      .replace(/\b(system|exec|popen|passthru|proc_open|shell_exec|eval)\b\s*\(/gi, '')
      .replace(/\b(ping|telnet|nslookup|traceroute|dig|wget|curl|nc|netcat)\b/gi, '')
      .replace(/\|\s*\w+/gi, '')
      .replace(/`.*`/g, '')
      .replace(/\$\([^)]*\)/g, '');
  };
  

  WVS.sanitizePath = function(path) {
    if (typeof path !== 'string') return '';
    
    let sanitized = path
      .replace(/\.\.\//g, '')
      .replace(/\.\.\\\\/g, '')
      .replace(/\.\.%2f/gi, '')
      .replace(/\.\.%5c/gi, '')
      .replace(/%252e%252e\//gi, '')
      .replace(/%252e%252e%255c/gi, '')
      .replace(/\.\.%c0%af/gi, '')
      .replace(/\.\.%c1%9c/gi, '');
    
    sanitized = sanitized.replace(/[\/\\]+/g, '/');
    
    return sanitized;
  };
  

  WVS.validateURL = function(url, allowedDomains = []) {
    if (typeof url !== 'string') return '';
    
    if (url.startsWith('/') || url.startsWith('./') || url.startsWith('../')) {
      return WVS.sanitizePath(url);
    }
    
    try {
      const parsedUrl = new URL(url);
      
      if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
        return '';
      }
      
      if (allowedDomains && allowedDomains.length > 0) {
        const isAllowed = allowedDomains.some(domain => {
          return parsedUrl.hostname === domain || 
                 parsedUrl.hostname.endsWith('.' + domain);
        });
        
        if (!isAllowed) {
          return '';
        }
      }
      
      return url;
    } catch (e) {
      return '';
    }
  };
  

  WVS.sanitizeObject = function(obj, sanitizer = WVS.sanitizeHTML) {
    if (!obj || typeof obj !== 'object') return obj;
    
    if (Array.isArray(obj)) {
      return obj.map(item => WVS.sanitizeObject(item, sanitizer));
    }
    
    const result = {};
    for (const key in obj) {
      if (Object.prototype.hasOwnProperty.call(obj, key)) {
        const value = obj[key];
        
        if (typeof value === 'string') {
          result[key] = sanitizer(value);
        } else if (typeof value === 'object' && value !== null) {
          result[key] = WVS.sanitizeObject(value, sanitizer);
        } else {
          result[key] = value;
        }
      }
    }
    
    return result;
  };
  

  WVS.encodeHTML = function(text) {
    if (typeof text !== 'string') return '';
    
    return text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  };
  

  WVS.createSafeElement = function(tagName, attributes = {}, content = '') {
    const element = document.createElement(tagName);
    
    for (const [key, value] of Object.entries(attributes)) {
      if (key.startsWith('on') || key === 'style') continue;
      
      let safeValue = value;
      if (key === 'href' || key === 'src') {
        safeValue = WVS.validateURL(value);
      } else {
        safeValue = WVS.encodeHTML(value);
      }
      
      element.setAttribute(key, safeValue);
    }
    
    if (typeof content === 'string') {
      element.textContent = content;
    } else if (Array.isArray(content)) {
      content.forEach(child => {
        if (child instanceof Node) {
          element.appendChild(child);
        }
      });
    }
    
    return element;
  };
  

  WVS.safeInnerHTML = function(element, html) {
    if (!element || !(element instanceof HTMLElement)) return;
    
    const sanitized = WVS.sanitizeHTML(html);
    element.innerHTML = sanitized;
  };
  

  WVS.containsXSS = function(input) {
    if (typeof input !== 'string') return false;
    
    const xssPatterns = [
      /<script\b[^>]*>([\s\S]*?)<\/script>/i,
      /javascript\s*:/i,
      /on\w+\s*=\s*["']?[^"'>\s]+/i,
      /eval\s*\(/i,
      /document\.cookie/i,
      /document\.write/i
    ];
    
    return xssPatterns.some(pattern => pattern.test(input));
  };
  

  WVS.containsSQLInjection = function(input) {
    if (typeof input !== 'string') return false;
    
    const sqlPatterns = [
      /\b(union|select|insert|update|delete|drop|alter)\b\s+/i,
      /'\s*(or|and)\s*['"]?\s*[0-9a-zA-Z]+['"]?\s*[=<>]/i,
      /'\s*;\s*[a-zA-Z]+/i
    ];
    
    return sqlPatterns.some(pattern => pattern.test(input));
  };

  WVS.protectForm = function(form) {
    if (!form || !(form instanceof HTMLFormElement)) return;
    
    form.addEventListener('submit', function(e) {
      const inputs = form.querySelectorAll('input:not([type="file"]), textarea');
      
      inputs.forEach(function(input) {
        if (WVS.containsXSS(input.value) || WVS.containsSQLInjection(input.value)) {
          e.preventDefault();
          
          const warning = WVS.createSafeElement('div', {
            style: 'color: red; border: 1px solid red; padding: 10px; margin: 5px 0;'
          }, 'Potentially malicious input detected. Please revise your input.');
          
          form.parentNode.insertBefore(warning, form);
          
          input.style.border = '2px solid red';
          
          input.focus();
          
          setTimeout(function() {
            if (warning.parentNode) {
              warning.parentNode.removeChild(warning);
            }
          }, 5000);
        }
      });
    });
  };
  

  WVS.protectAllForms = function() {
    const forms = document.querySelectorAll('form');
    forms.forEach(WVS.protectForm);
  };
  
  window.WebVulnerabilityShield = WVS;
  
  if (window.wvsConfig && window.wvsConfig.autoProtectForms) {
    document.addEventListener('DOMContentLoaded', function() {
      WVS.protectAllForms();
    });
  }
})();