(function() {
  'use strict';

  window.WebVaxSanitize = {
    sanitizeHTML: function(input) {
      if (typeof input !== 'string') return '';

      return input
        .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gmi, '')
        .replace(/javascript\s*:/gmi, 'void:')
        .replace(/on\w+\s*=\s*["']?[^"'>\s]+/gmi, '')
        .replace(/data\s*:\s*text\/html/gmi, 'data:invalid')
        .replace(/eval\s*\(/gmi, 'void(')
        .replace(/document\.cookie/gmi, 'void(0)')
        .replace(/[<>"'`;]/g, match => ({
          '<': '&lt;',
          '>': '&gt;',
          '"': '&quot;',
          "'": '&#x27;',
          '`': '&#x60;',
          ';': '&#x3B;'
        }[match]));
    },

    sanitizeURL: function(url) {
      if (typeof url !== 'string') return '#';

      try {
        const parsed = new URL(url, window.location.href);
        if (/[?&](url|redirect|redir|next|goto|to)=/i.test(parsed.search)) {
          return '#';
        }
        return parsed.toString()
          .replace(/javascript\s*:/gmi, 'void:')
          .replace(/data\s*:\s*text\/html/gmi, 'data:invalid');
      } catch (e) {
        return '#';
      }
    },

    sanitizeInput: function(input) {
      if (typeof input !== 'string') return '';

      return input
        .replace(/[<>;"'`|&]/g, '')
        .replace(/\b(select|insert|update|delete|drop|alter|union|exec)\b/gi, '')
        .replace(/--|#|\/\*|\*\//g, '')
        .replace(/(\.\.\/|\.\.\\\\)/g, '');
    }
  };
})();