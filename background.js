
const config = {
    enabled: true,
    logLevel: 'info',
    vulnerabilities: {
      xss: { enabled: true, level: 'high' },
      sqlInjection: { enabled: true, level: 'high' },
      commandInjection: { enabled: true, level: 'high' },
      pathTraversal: { enabled: true, level: 'high' },
      openRedirect: { enabled: true, level: 'high' }
    },
    whitelistedDomains: [],
    notificationThreshold: 'medium' 
  };
  
  chrome.storage.local.get('securityConfig', (result) => {
    if (result.securityConfig) {
      Object.assign(config, result.securityConfig);
    } else {
      chrome.storage.local.set({ securityConfig: config });
    }
  });
  
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
  
  const detectionEngines = {
    xss: new XSSDetectionEngine(),
    sqlInjection: new SQLInjectionDetectionEngine(),
    commandInjection: new CommandInjectionDetectionEngine(),
    pathTraversal: new PathTraversalDetectionEngine(),
    openRedirect: new OpenRedirectDetectionEngine()
  };
  
  function XSSDetectionEngine() {
    const xssPatterns = [
      /<script\b[^>]*>([\s\S]*?)<\/script>/gmi,
      /javascript\s*:/gmi,
      /on\w+\s*=\s*"[^"]*"/gmi,
      /on\w+\s*=\s*'[^']*'/gmi,
      /on\w+\s*=[^\s>]+/gmi,
      /<\s*img[^>]+src\s*=\s*["']?[^"'>]+["']?[^>]*>/gmi,
      /<\s*iframe[^>]+src\s*=\s*["']?[^"'>]+["']?[^>]*>/gmi,
      /data\s*:\s*text\/html/gmi,
      /expression\s*\(/gmi,
      /document\.cookie/gmi,
      /document\.location/gmi,
      /document\.write/gmi,
      /eval\s*\(/gmi,
      /setTimeout\s*\(/gmi,
      /setInterval\s*\(/gmi,
      /new\s+Function\s*\(/gmi,
      /alert\s*\(/gmi,
      /prompt\s*\(/gmi,
      /confirm\s*\(/gmi
    ];
    
    const contextualPatterns = {
      urlContext: [/['"]\s*\+\s*[^+;]*\s*\+\s*['"]|['"][\s\S]*\$\{.*\}[\s\S]*['"]|['"][\s\S]*\$\(.*\)[\s\S]*['"]/gi],
      htmlContext: [/<(\w+)\s+[^>]*?[\s"';](on\w+)\s*=|<(\w+)\s+[^>]*?style\s*=\s*["']?\s*(expression|behavior)\s*:/gi],
      jsContext: [/(?:\beval\s*\(|\bdocument\.write\s*\(|\bwindow\.location\s*=|\bdocument\.cookie\s*=|\bdocument\.domain\s*=)/gi]
    };
  
    this.detect = function(input, context = 'general') {
      if (typeof input !== 'string') return false;
      
      for (const pattern of xssPatterns) {
        if (pattern.test(input)) {
          return { detected: true, pattern: pattern.toString(), context: 'general' };
        }
      }
      
      if (contextualPatterns[context]) {
        for (const pattern of contextualPatterns[context]) {
          if (pattern.test(input)) {
            return { detected: true, pattern: pattern.toString(), context };
          }
        }
      }
      
      const riskScore = this.calculateRiskScore(input);
      if (riskScore > 0.7) {  // Threshold
        return { detected: true, pattern: 'heuristic', riskScore, context };
      }
      
      return { detected: false };
    };
    
    this.calculateRiskScore = function(input) {
      let score = 0;
      
      const charCount = input.length;
      const specialChars = (input.match(/[<>'"();{}]/g) || []).length;
      score += (specialChars / charCount) * 0.4;
      
      const encodedChars = (input.match(/&#\d+;|&#x[a-f0-9]+;|%[a-f0-9]{2}/gi) || []).length;
      score += (encodedChars > 0) ? Math.min(encodedChars / 10, 0.3) : 0;
      
      const alphabeticChars = input.match(/[a-zA-Z]/g) || [];
      if (alphabeticChars.length > 5) {
        const upperCount = input.match(/[A-Z]/g)?.length || 0;
        const lowerCount = input.match(/[a-z]/g)?.length || 0;
        const mixedCaseRatio = Math.min(upperCount, lowerCount) / Math.max(upperCount, lowerCount);
        if (mixedCaseRatio > 0.3 && mixedCaseRatio < 0.7) {
          score += 0.2;
        }
      }
      
      if (charCount > 150) score += 0.1;
      
      return Math.min(score, 1);  // Cap at 1
    };
    
    this.sanitize = function(input) {
      return input
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;')
        .replace(/\//g, '&#x2F;')
        .replace(/\\/g, '&#x5C;')
        .replace(/`/g, '&#96;');
    };
  }
  
  function SQLInjectionDetectionEngine() {
    const sqlPatterns = [
      /\b(union|select|insert|update|delete|drop|alter)\b\s+/gi,
      /'\s*(or|and)\s*['"]?\s*[0-9a-zA-Z]+['"]?\s*[=<>]/gi,
      /'\s*;\s*[a-zA-Z]+/gi,
      /(\%27)|(\')|(\-\-)|(\%23)|(#)/gi,
      /(((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(\;)))/gi,
      /((\%27)|(\'))union/gi,
      /exec(\s|\+)+(s|x)p\w+/gi,
      /SLEEP\([^\)]*\)/gi,
      /BENCHMARK\([^\)]*\)/gi,
      /WAITFOR DELAY/gi
    ];
    
    const sqlSyntaxElements = [
      { pattern: /\b(select|from|where|having|group by|order by)\b/gi, weight: 0.2 },
      { pattern: /\b(union|join|inner join|left join|right join)\b/gi, weight: 0.3 },
      { pattern: /\b(insert|update|delete|drop|alter|create|truncate)\b/gi, weight: 0.4 },
      { pattern: /\b(exec|execute|sp_|xp_)\b/gi, weight: 0.5 },
      { pattern: /\b(declare|set|cast|convert)\b/gi, weight: 0.2 },
      { pattern: /(--|#|\/\*|\*\/)/g, weight: 0.3 },
      { pattern: /(\bor\b|\band\b)(\s+\d+\s*=\s*\d+|\s+'[^']*'\s*=\s*'[^']*')/gi, weight: 0.5 },
      { pattern: /['"]\s*(\+|;)\s*['"]/gi, weight: 0.4 }
    ];
    
    this.detect = function(input) {
      if (typeof input !== 'string') return false;
      
      for (const pattern of sqlPatterns) {
        if (pattern.test(input)) {
          return { detected: true, pattern: pattern.toString() };
        }
      }
      
      const riskScore = this.calculateRiskScore(input);
      if (riskScore > 0.7) {  // Threshold
        return { detected: true, pattern: 'heuristic', riskScore };
      }
      
      return { detected: false };
    };
    
    this.calculateRiskScore = function(input) {
      let score = 0;
      
      for (const element of sqlSyntaxElements) {
        const matches = input.match(element.pattern) || [];
        score += matches.length * element.weight;
      }
      
      const singleQuotes = (input.match(/'/g) || []).length;
      const doubleQuotes = (input.match(/"/g) || []).length;
      if ((singleQuotes % 2 !== 0) || (doubleQuotes % 2 !== 0)) {
        score += 0.3;
      }
      
      const encodedChars = (input.match(/%[0-9a-f]{2}/gi) || []).length;
      score += (encodedChars > 0) ? Math.min(encodedChars / 10, 0.2) : 0;
      
      return Math.min(score, 1);  
    };
    
    this.sanitize = function(input) {
      return input
        .replace(/'/g, "''")
        .replace(/;/g, "")
        .replace(/--/g, "")
        .replace(/\/\*/g, "")
        .replace(/\*\//g, "")
        .replace(/xp_/gi, "")
        .replace(/sp_/gi, "")
        .replace(/exec/gi, "")
        .replace(/union\s+select/gi, "")
        .replace(/select/gi, "")
        .replace(/insert/gi, "")
        .replace(/update/gi, "")
        .replace(/delete/gi, "")
        .replace(/drop/gi, "")
        .replace(/alter/gi, "");
    };
  }
  
  function CommandInjectionDetectionEngine() {
    const commandPatterns = [
      /\b(system|exec|popen|passthru|proc_open|shell_exec|eval)\b\s*\(/gi,
      /[&|;`$><]/g,
      /\b(ping|telnet|nslookup|traceroute|dig|wget|curl|nc|netcat)\b/gi,
      /\|\s*\w+/gi,
      /`.*`/g,
      /\$\([^)]*\)/g,
      /\b(cat|tac|more|less|head|tail|grep|awk|sed|find|locate|ls|dir|pwd)\b/gi,
      /\b(rm|cp|mv|mkdir|rmdir|touch|chmod|chown|chgrp)\b/gi
    ];
  
    const osSpecificPatterns = {
      unix: [
        /\/(bin|etc|usr|var|tmp|home)\//gi,
        /\b(bash|sh|dash|ksh|csh|zsh)\b/gi,
        /\b(sudo|su)\b/gi
      ],
      windows: [
        /\b(cmd\.exe|powershell\.exe|cscript\.exe|wscript\.exe)\b/gi,
        /\b(type|echo|more|findstr|tasklist|net\s+user|net\s+localgroup)\b/gi,
        /%[a-zA-Z0-9_]+%/g
      ]
    };
    
    this.detect = function(input) {
      if (typeof input !== 'string') return false;
      
      for (const pattern of commandPatterns) {
        if (pattern.test(input)) {
          return { detected: true, pattern: pattern.toString() };
        }
      }
      
      for (const os in osSpecificPatterns) {
        for (const pattern of osSpecificPatterns[os]) {
          if (pattern.test(input)) {
            return { detected: true, pattern: pattern.toString(), os };
          }
        }
      }
      
      const riskScore = this.calculateRiskScore(input);
      if (riskScore > 0.6) {  
        return { detected: true, pattern: 'heuristic', riskScore };
      }
      
      return { detected: false };
    };
    
    this.calculateRiskScore = function(input) {
      let score = 0;
      
      const chainOperators = (input.match(/[&|;]/g) || []).length;
      score += chainOperators * 0.15;
      
      const redirectionOperators = (input.match(/[><]/g) || []).length;
      score += redirectionOperators * 0.1;
      
      const commandSubstitution = (input.match(/`|(\$\()/g) || []).length;
      score += commandSubstitution * 0.2;
      
      if (/\s+[&|;]\s*\w+/.test(input)) score += 0.3;
      if (/\$\w+/.test(input)) score += 0.2;  
      
      if (/\/[\w\/]+/.test(input) || /[a-zA-Z]:\\/.test(input)) score += 0.2;
      
      return Math.min(score, 1);  // Cap at 1
    };
    
    this.sanitize = function(input) {
      return input
        .replace(/[&|;`$><]/g, "")
        .replace(/\b(system|exec|popen|passthru|proc_open|shell_exec|eval)\b\s*\(/gi, "")
        .replace(/\b(ping|telnet|nslookup|traceroute|dig|wget|curl|nc|netcat)\b/gi, "")
        .replace(/\b(cat|tac|more|less|head|tail|grep|awk|sed|find|locate|ls|dir|pwd)\b/gi, "")
        .replace(/\b(rm|cp|mv|mkdir|rmdir|touch|chmod|chown|chgrp)\b/gi, "")
        .replace(/`.*`/g, "")
        .replace(/\$\([^)]*\)/g, "");
    };
  }
  
  function PathTraversalDetectionEngine() {
    const pathPatterns = [
      /\.\.\//g,
      /\.\.%2f/gi,
      /\.\.\\\//g,
      /\.\.%5c/gi,
      /%252e%252e\//gi,
      /%252e%252e%255c/gi,
      /\.\.%c0%af/gi,
      /\.\.%c1%9c/gi,
      /\.\.\%255c/gi
    ];
    
    const sensitiveFilePatterns = [
      /\b(passwd|shadow|htpasswd|web\.config|\.env|\.git|\.svn)\b/gi,
      /\b(wp-config\.php|configuration\.php|config\.php|settings\.php)\b/gi,
      /\b(boot\.ini|win\.ini|system\.ini)\b/gi,
      /\b(access\.log|error\.log|debug\.log)\b/gi,
      /\b(id_rsa|id_dsa|\.ssh\/|authorized_keys)\b/gi
    ];
    
    this.detect = function(input) {
      if (typeof input !== 'string') return false;
      
      for (const pattern of pathPatterns) {
        if (pattern.test(input)) {
          return { detected: true, pattern: pattern.toString() };
        }
      }
      
      if (this.containsPathTraversalSequence(input)) {
        for (const pattern of sensitiveFilePatterns) {
          if (pattern.test(input)) {
            return { detected: true, pattern: pattern.toString(), sensitiveFile: true };
          }
        }
      }
      
      const riskScore = this.calculateRiskScore(input);
      if (riskScore > 0.5) {  
        return { detected: true, pattern: 'heuristic', riskScore };
      }
      
      return { detected: false };
    };
    
    this.containsPathTraversalSequence = function(input) {
      return /\.\.[\\/]/.test(input) || 
             /\.\.%2f/i.test(input) || 
             /\.\.%5c/i.test(input) ||
             /%252e%252e/i.test(input);
    };
    
    this.calculateRiskScore = function(input) {
      let score = 0;
      
      const dotDotSlash = (input.match(/\.\.[\\\/]/g) || []).length;
      score += dotDotSlash * 0.3;
      
      const encodedDotDot = (input.match(/%2e%2e|%252e%252e/gi) || []).length;
      score += encodedDotDot * 0.4;
      
      if (/^\/[a-z0-9_\-\.\/]+$/i.test(input) || /^[a-z]:\\[a-z0-9_\-\.\\]+$/i.test(input)) {
        score += 0.2;
      }
      
      if (/\.(conf|config|ini|log|passwd|properties|xml|yml|yaml)$/i.test(input)) {
        score += 0.3;
      }
      
      return Math.min(score, 1);  
    };
    
    this.sanitize = function(input) {
      let sanitized = input
        .replace(/\.\.\//g, "")
        .replace(/\.\.%2f/gi, "")
        .replace(/\.\.\\\//g, "")
        .replace(/\.\.%5c/gi, "")
        .replace(/%252e%252e\//gi, "")
        .replace(/%252e%252e%255c/gi, "")
        .replace(/\.\.%c0%af/gi, "")
        .replace(/\.\.%c1%9c/gi, "")
        .replace(/\.\.\%255c/gi, "");
      
      sanitized = sanitized.replace(/[\/\\]+/g, "/");
      
      return sanitized;
    };
  }
  
  function OpenRedirectDetectionEngine() {
    const redirectPatterns = [
      /[?&](url|redirect|redir|next|goto|to|link|return|returnto|returnurl|location|path)=/i,
      /(https?|ftp):\/\/[^\s/$.?#].[^\s]*$/i
    ];
    
    const suspiciousDomainPatterns = [
      /(evil|malicious|hack|phish|steal|attack).*\.(com|net|org|io|xyz)/i,
      /^(?!.*\.(com|org|net|gov|edu|io|co|us)).*$/i
    ];
    
    this.detect = function(input) {
      if (typeof input !== 'string') return false;
      
      const urls = this.extractUrls(input);
      
      if (urls.length === 0) return { detected: false };
      
      for (const pattern of redirectPatterns) {
        if (pattern.test(input)) {
          for (const url of urls) {
            if (this.isExternalDomain(url)) {
              return { detected: true, pattern: pattern.toString(), url };
            }
          }
        }
      }
      
      for (const url of urls) {
        for (const pattern of suspiciousDomainPatterns) {
          if (pattern.test(url)) {
            return { detected: true, pattern: pattern.toString(), url, suspiciousDomain: true };
          }
        }
      }
      
      const riskScore = this.calculateRiskScore(input);
      if (riskScore > 0.6) {  
        return { detected: true, pattern: 'heuristic', riskScore };
      }
      
      return { detected: false };
    };
    
    this.extractUrls = function(input) {
      const urlRegex = /(https?|ftp):\/\/[^\s/$.?#].[^\s]*/gi;
      return input.match(urlRegex) || [];
    };
    
    this.isExternalDomain = function(url) {
      try {
        const parsedUrl = new URL(url);
        return !parsedUrl.hostname.includes('localhost') && 
               !parsedUrl.hostname.includes('127.0.0.1');
      } catch (e) {
        return false;
      }
    };
    
    this.calculateRiskScore = function(input) {
      let score = 0;
      
      if (/[?&](to|url|redirect|redir|next|goto|link)=/i.test(input)) score += 0.3;
      
      const percentEncoding = (input.match(/%[0-9a-f]{2}/gi) || []).length;
      score += (percentEncoding > 5) ? 0.2 : 0;
      
      if (/[?&][^=]+=([a-zA-Z0-9+/]{30,}=*)/.test(input)) score += 0.3;
      
      if (/https?:\/\/[^/]*\.[^/]*\.[^/]*\.[^/]*\.[^/]*\//.test(input)) score += 0.2;
      
      if (/https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(input)) score += 0.3;
      
      return Math.min(score, 1);  // Cap at 1
    };
    
    this.sanitize = function(input) {
      const urls = this.extractUrls(input);
      let sanitized = input;
      
      for (const url of urls) {
        if (this.isExternalDomain(url)) {
          sanitized = sanitized.replace(url, "#");
        }
      }
      
      return sanitized;
    };
  }
  
  chrome.webRequest.onBeforeRequest.addListener(
    function(details) {
      if (!config.enabled) return { cancel: false };
      
      const url = new URL(details.url);
      if (config.whitelistedDomains.includes(url.hostname)) {
        return { cancel: false };
      }
      
      const requestData = {
        url: details.url,
        method: details.method,
        type: details.type,
        timeStamp: details.timeStamp,
        requestId: details.requestId,
        body: null
      };
      
    if (details.method === 'POST' || details.method === 'PUT') {
        if (details.requestBody) {
          if (details.requestBody.formData) {
            requestData.body = details.requestBody.formData;
          } else if (details.requestBody.raw) {
            const decoder = new TextDecoder();
            requestData.body = decoder.decode(details.requestBody.raw[0].bytes);
          }
        }
      }
      
      const urlParams = new URLSearchParams(url.search);
      const paramMap = {};
      urlParams.forEach((value, key) => {
        paramMap[key] = value;
      });
      requestData.params = paramMap;
      
      const vulnerabilities = analyzeRequest(requestData);
      
      if (vulnerabilities.length > 0) {
        logVulnerabilities(vulnerabilities, requestData);
        
        const highSeverityVulnerability = vulnerabilities.find(v => v.severity === 'high');
        if (highSeverityVulnerability && highSeverityVulnerability.action === 'block') {
          notifyUser('Blocked a high-risk request to ' + url.hostname, highSeverityVulnerability);
          return { cancel: true };
        } else {
          chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
            if (tabs[0]) {
              chrome.tabs.sendMessage(tabs[0].id, {
                action: 'vulnerabilityDetected',
                vulnerabilities: vulnerabilities,
                requestData: requestData
              });
            }
          });
        }
      }
      
      return { cancel: false };
    },
    { urls: ["<all_urls>"] },
    ["blocking", "requestBody"]
  );
  
  function analyzeRequest(requestData) {
    const vulnerabilities = [];
    
    function checkData(data, context = 'general') {
      if (!data || typeof data !== 'string') return;
      
      if (config.vulnerabilities.xss.enabled) {
        const xssResult = detectionEngines.xss.detect(data, context);
        if (xssResult.detected) {
          vulnerabilities.push({
            type: 'xss',
            severity: config.vulnerabilities.xss.level,
            details: xssResult,
            payload: data,
            action: config.vulnerabilities.xss.level === 'high' ? 'block' : 'sanitize',
            sanitized: detectionEngines.xss.sanitize(data)
          });
        }
      }
      
      if (config.vulnerabilities.sqlInjection.enabled) {
        const sqlResult = detectionEngines.sqlInjection.detect(data);
        if (sqlResult.detected) {
          vulnerabilities.push({
            type: 'sqlInjection',
            severity: config.vulnerabilities.sqlInjection.level,
            details: sqlResult,
            payload: data,
            action: config.vulnerabilities.sqlInjection.level === 'high' ? 'block' : 'sanitize',
            sanitized: detectionEngines.sqlInjection.sanitize(data)
          });
        }
      }
      
      if (config.vulnerabilities.commandInjection.enabled) {
        const cmdResult = detectionEngines.commandInjection.detect(data);
        if (cmdResult.detected) {
          vulnerabilities.push({
            type: 'commandInjection',
            severity: config.vulnerabilities.commandInjection.level,
            details: cmdResult,
            payload: data,
            action: config.vulnerabilities.commandInjection.level === 'high' ? 'block' : 'sanitize',
            sanitized: detectionEngines.commandInjection.sanitize(data)
          });
        }
      }
      
      if (config.vulnerabilities.pathTraversal.enabled) {
        const pathResult = detectionEngines.pathTraversal.detect(data);
        if (pathResult.detected) {
          vulnerabilities.push({
            type: 'pathTraversal',
            severity: config.vulnerabilities.pathTraversal.level,
            details: pathResult,
            payload: data,
            action: config.vulnerabilities.pathTraversal.level === 'high' ? 'block' : 'sanitize',
            sanitized: detectionEngines.pathTraversal.sanitize(data)
          });
        }
      }
      
      if (config.vulnerabilities.openRedirect.enabled) {
        const redirectResult = detectionEngines.openRedirect.detect(data);
        if (redirectResult.detected) {
          vulnerabilities.push({
            type: 'openRedirect',
            severity: config.vulnerabilities.openRedirect.level,
            details: redirectResult,
            payload: data,
            action: config.vulnerabilities.openRedirect.level === 'high' ? 'block' : 'sanitize',
            sanitized: detectionEngines.openRedirect.sanitize(data)
          });
        }
      }
    }
    
    if (requestData.params) {
      for (const [key, value] of Object.entries(requestData.params)) {
        checkData(value, 'urlContext');
      }
    }
    
    if (requestData.body) {
      if (typeof requestData.body === 'string') {
        checkData(requestData.body);
      } else if (typeof requestData.body === 'object') {
        for (const [key, values] of Object.entries(requestData.body)) {
          if (Array.isArray(values)) {
            values.forEach(value => checkData(value));
          } else {
            checkData(values);
          }
        }
      }
    }
    
    if (config.vulnerabilities.pathTraversal.enabled) {
      const url = new URL(requestData.url);
      const pathResult = detectionEngines.pathTraversal.detect(url.pathname);
      if (pathResult.detected) {
        vulnerabilities.push({
          type: 'pathTraversal',
          severity: config.vulnerabilities.pathTraversal.level,
          details: pathResult,
          payload: url.pathname,
          action: config.vulnerabilities.pathTraversal.level === 'high' ? 'block' : 'sanitize',
          sanitized: detectionEngines.pathTraversal.sanitize(url.pathname)
        });
      }
    }
    
    return vulnerabilities;
  }
  
  function logVulnerabilities(vulnerabilities, requestData) {
    vulnerabilities.forEach(vulnerability => {
      threatStats.totalThreatsDetected++;
      threatStats.threatsByType[vulnerability.type]++;
      
      const threatInfo = {
        timestamp: new Date().toISOString(),
        type: vulnerability.type,
        severity: vulnerability.severity,
        url: requestData.url,
        payload: vulnerability.payload.substring(0, 100) 
      };
      
      threatStats.recentThreats.unshift(threatInfo);
      if (threatStats.recentThreats.length > 100) {
        threatStats.recentThreats.pop();
      }
      
      if (config.logLevel === 'debug' || config.logLevel === 'info') {
        console.log('[WebVax] Detected:', {
          type: vulnerability.type,
          severity: vulnerability.severity,
          url: requestData.url,
          details: vulnerability.details
        });
      }
      
      chrome.storage.local.set({ threatStats: threatStats });
    });
  }
  
  function notifyUser(message, vulnerability) {
    const severityMap = { 'low': 1, 'medium': 2, 'high': 3 };
    const thresholdMap = { 'low': 1, 'medium': 2, 'high': 3 };
    
    if (severityMap[vulnerability.severity] >= thresholdMap[config.notificationThreshold]) {
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icons/icon48.png',
        title: 'WebVax',
        message: message,
        priority: 1
      });
    }
  }
  
  chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
    if (request.action === 'getConfig') {
      sendResponse({ config: config });
    } else if (request.action === 'updateConfig') {
      Object.assign(config, request.config);
      chrome.storage.local.set({ securityConfig: config });
      sendResponse({ success: true });
    } else if (request.action === 'getThreatStats') {
      sendResponse({ threatStats: threatStats });
    } else if (request.action === 'resetThreatStats') {
      threatStats = {
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
      chrome.storage.local.set({ threatStats: threatStats });
      sendResponse({ success: true });
    } else if (request.action === 'scanPage') {
      chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
        if (tabs[0]) {
          chrome.tabs.sendMessage(tabs[0].id, { action: 'scanPage' });
        }
      });
      sendResponse({ success: true });
    }
    
    return true;
  });
  
  chrome.runtime.onInstalled.addListener(function(details) {
    if (details.reason === 'install') {
      chrome.tabs.create({ url: 'welcome.html' });
    } else if (details.reason === 'update') {
    }
  });