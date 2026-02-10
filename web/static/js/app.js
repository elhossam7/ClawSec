// ================================================================
// Sentinel — Cyber Defense Dashboard
// Frontend Interactivity (no framework, htmx-powered)
// ================================================================

(function () {
  'use strict';

  // ────────────────────────────────────────────
  // Sidebar Toggle (mobile)
  // ────────────────────────────────────────────
  window.toggleSidebar = function () {
    var sidebar = document.getElementById('sidebar');
    var overlay = document.getElementById('sidebar-overlay');
    if (sidebar) {
      sidebar.classList.toggle('open');
      if (overlay) overlay.classList.toggle('active');
    }
  };

  // Close sidebar when clicking overlay
  document.addEventListener('click', function (e) {
    if (e.target && e.target.id === 'sidebar-overlay') {
      var sidebar = document.getElementById('sidebar');
      if (sidebar) sidebar.classList.remove('open');
      e.target.classList.remove('active');
    }
  });

  // ────────────────────────────────────────────
  // Active Navigation Tracking
  // ────────────────────────────────────────────
  function updateActiveNav() {
    var path = window.location.pathname;
    var items = document.querySelectorAll('.nav-item');
    items.forEach(function (item) {
      var href = item.getAttribute('href');
      item.classList.remove('active');
      if (href === path) {
        item.classList.add('active');
      } else if (href !== '/' && path.startsWith(href)) {
        item.classList.add('active');
      }
    });

    // Update topbar title
    var titles = {
      '/': 'Dashboard',
      '/incidents': 'Incidents',
      '/approval': 'Approval Queue',
      '/rules': 'Detection Rules',
      '/audit': 'Audit Log',
    };
    var topbarTitle = document.querySelector('.topbar-title');
    if (topbarTitle && titles[path]) {
      topbarTitle.textContent = titles[path];
    }
  }

  document.addEventListener('htmx:pushedIntoHistory', updateActiveNav);
  document.addEventListener('htmx:replacedInHistory', updateActiveNav);

  // ────────────────────────────────────────────
  // SSE: Toast Notifications
  // ────────────────────────────────────────────
  document.addEventListener('htmx:sseMessage', function (e) {
    if (e.detail.type === 'notification') {
      var container = document.getElementById('toast-container');
      if (!container) return;
      var toasts = container.querySelectorAll('.toast');
      toasts.forEach(function (toast) {
        if (toast._dismissTimer) return;
        toast._dismissTimer = setTimeout(function () {
          toast.style.animation = 'toast-out 0.3s ease-in forwards';
          setTimeout(function () {
            toast.remove();
          }, 320);
        }, 8000);
      });
    }
  });

  // ────────────────────────────────────────────
  // SSE: Event Stream — auto-scroll & limit
  // ────────────────────────────────────────────
  document.addEventListener('htmx:sseMessage', function (e) {
    if (e.detail.type === 'new_event') {
      var stream = document.getElementById('event-stream');
      if (!stream) return;
      stream.scrollTop = 0;
      // Cap visible events at 120
      var rows = stream.querySelectorAll('.event-row');
      for (var i = 120; i < rows.length; i++) {
        rows[i].remove();
      }
    }
  });

  // ────────────────────────────────────────────
  // SSE: Pending Badge + Tab Title
  // ────────────────────────────────────────────
  document.addEventListener('htmx:sseMessage', function (e) {
    if (e.detail.type === 'pending_count') {
      var count = parseInt(e.detail.data, 10) || 0;
      var badge = document.getElementById('pending-badge');
      if (badge) {
        if (count > 0) {
          badge.textContent = count;
          badge.style.display = 'inline-flex';
        } else {
          badge.style.display = 'none';
        }
      }
      document.title = count > 0 ? '(' + count + ') Sentinel' : 'Sentinel';
    }
  });

  // ────────────────────────────────────────────
  // Confirm Destructive Actions
  // ────────────────────────────────────────────
  document.addEventListener('htmx:confirm', function (e) {
    if (!e.detail.question) return;
    e.preventDefault();
    if (confirm(e.detail.question)) {
      e.detail.issueRequest();
    }
  });

  // ────────────────────────────────────────────
  // Page Swap Transitions
  // ────────────────────────────────────────────
  document.addEventListener('htmx:beforeSwap', function (e) {
    var target = e.detail.target;
    if (target && target.id === 'main-content') {
      target.style.opacity = '0';
      target.style.transform = 'translateY(6px)';
    }
  });

  document.addEventListener('htmx:afterSwap', function (e) {
    var target = e.detail.target;
    if (target && target.id === 'main-content') {
      requestAnimationFrame(function () {
        target.style.transition =
          'opacity 0.25s ease, transform 0.25s ease';
        target.style.opacity = '1';
        target.style.transform = 'translateY(0)';
      });
      // Re-init counters on page swap
      setTimeout(initCounters, 30);
    }

    // Close mobile sidebar after navigation
    var sidebar = document.getElementById('sidebar');
    if (sidebar) sidebar.classList.remove('open');
    var overlay = document.getElementById('sidebar-overlay');
    if (overlay) overlay.classList.remove('active');
  });

  // ────────────────────────────────────────────
  // Animated Counter Effect
  // ────────────────────────────────────────────
  function initCounters() {
    var els = document.querySelectorAll('[data-counter]');
    els.forEach(function (el) {
      var target = parseInt(el.getAttribute('data-counter'), 10);
      if (isNaN(target)) return;
      if (target === 0) {
        el.textContent = '0';
        return;
      }

      var duration = 700;
      var startTime = null;

      function step(ts) {
        if (!startTime) startTime = ts;
        var progress = Math.min((ts - startTime) / duration, 1);
        // ease-out cubic
        var eased = 1 - Math.pow(1 - progress, 3);
        el.textContent = Math.round(target * eased).toLocaleString();
        if (progress < 1) requestAnimationFrame(step);
      }
      requestAnimationFrame(step);
    });
  }

  // ────────────────────────────────────────────
  // Dashboard Auto-Refresh (every 30s)
  // ────────────────────────────────────────────
  var dashboardTimer = null;

  function startDashboardRefresh() {
    stopDashboardRefresh();
    if (window.location.pathname === '/') {
      dashboardTimer = setInterval(function () {
        if (window.location.pathname === '/') {
          htmx.ajax('GET', '/', {
            target: '#main-content',
            swap: 'innerHTML',
          });
        } else {
          stopDashboardRefresh();
        }
      }, 30000);
    }
  }

  function stopDashboardRefresh() {
    if (dashboardTimer) {
      clearInterval(dashboardTimer);
      dashboardTimer = null;
    }
  }

  // ────────────────────────────────────────────
  // Uptime Counter (increments in the top bar)
  // ────────────────────────────────────────────
  var uptimeSeconds = 0;

  function startUptimeCounter() {
    var el = document.getElementById('uptime-display');
    if (!el) return;

    function tick() {
      uptimeSeconds++;
      var d = Math.floor(uptimeSeconds / 86400);
      var h = Math.floor((uptimeSeconds % 86400) / 3600);
      var m = Math.floor((uptimeSeconds % 3600) / 60);
      var s = uptimeSeconds % 60;

      if (d > 0) {
        el.textContent = d + 'd ' + h + 'h';
      } else if (h > 0) {
        el.textContent = h + 'h ' + m + 'm';
      } else if (m > 0) {
        el.textContent = m + 'm ' + s + 's';
      } else {
        el.textContent = s + 's';
      }
    }
    setInterval(tick, 1000);
    tick();
  }

  // ────────────────────────────────────────────
  // Keyboard Shortcuts
  // ────────────────────────────────────────────
  document.addEventListener('keydown', function (e) {
    // Don't trigger inside inputs/textareas
    var tag = e.target.tagName;
    if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return;
    if (e.ctrlKey || e.metaKey || e.altKey) return;

    var routes = {
      d: '/',
      i: '/incidents',
      a: '/approval',
      r: '/rules',
      l: '/audit',
    };

    if (routes[e.key]) {
      e.preventDefault();
      htmx.ajax('GET', routes[e.key], {
        target: '#main-content',
        swap: 'innerHTML',
      });
      history.pushState({}, '', routes[e.key]);
      updateActiveNav();
    }
  });

  // ────────────────────────────────────────────
  // Init on DOM Ready
  // ────────────────────────────────────────────
  document.addEventListener('DOMContentLoaded', function () {
    initCounters();
    startDashboardRefresh();
    startUptimeCounter();
    updateActiveNav();
  });

  // Re-start dashboard refresh on popstate (back/forward)
  window.addEventListener('popstate', function () {
    updateActiveNav();
    if (window.location.pathname === '/') {
      startDashboardRefresh();
    } else {
      stopDashboardRefresh();
    }
  });
})();
