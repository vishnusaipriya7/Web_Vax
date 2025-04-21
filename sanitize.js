(function() {
  'use strict';

  const trustedDomains = [
    'google.com',
    'youtube.com',
    'facebook.com',
    'amazon.com',
    'cloudflare.com',
    'localhost'
  ];

  window.WebVaxSanitize = {
    sanitizeHTML: function(input) {
      if (typeof input !== 'string') return '';
      let sanitized = input
        .replace(/<script\b[^>]*>[\s\S]*?(<\/script>|$)/gmi, '')
        .replace(/%3Cscript%3E[\s\S]*?(%3C%2Fscript%3E|$)/gmi, '')
        .replace(/javascript\s*:/gmi, 'void:')
        .replace(/on\w+\s*=\s*["']?[^"'>\s]+/gmi, '')
        .replace(/eval\s*\(/gmi, 'void(')
        .replace(/[<>"'`]/g, match => ({
          '<': '<',
          '>': '>',
          '"': '"',
          "'": "'",
          '`': '`'
        }[match]));
      if (sanitized !== input) {
        console.log('[WebVax] Sanitized HTML:', { original: input.substring(0, 100), sanitized: sanitized.substring(0, 100) });
      }
      return sanitized;
    },

    sanitizeURL: function(url) {
      if (typeof url !== 'string') return '#';

      try {
        const parsed = new URL(url, window.location.href);
        if (trustedDomains.some(domain => parsed.hostname === domain || parsed.hostname.endsWith('.' + domain))) {
          return url;
        }
        if (/[?&](url|redirect|redir|next|goto|to)=/i.test(parsed.search)) {
          return '#';
        }
        return parsed.toString().replace(/javascript\s*:/gmi, 'void:');
      } catch (e) {
        return '#';
      }
    },

    sanitizeInput: function(input) {
      if (typeof input !== 'string') return '';
      return input
        .replace(/[<>;"'`|]/g, '')
        .replace(/\b(union\s+select|exec\s+\w+|drop\s+table)\b/gi, '');
    }
  };
})();