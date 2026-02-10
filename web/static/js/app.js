// Sentinel WebUI - htmx enhancements (no framework)

// Auto-dismiss toast notifications after 8 seconds.
document.addEventListener('htmx:sseMessage', function(event) {
    if (event.detail.type === 'notification') {
        const container = document.getElementById('toast-container');
        const toasts = container.querySelectorAll('.toast');
        toasts.forEach(function(toast) {
            setTimeout(function() {
                toast.style.animation = 'slideIn 0.3s ease-out reverse';
                setTimeout(function() { toast.remove(); }, 300);
            }, 8000);
        });
    }
});

// Auto-scroll event stream to top on new events.
document.addEventListener('htmx:sseMessage', function(event) {
    if (event.detail.type === 'new_event') {
        var stream = document.getElementById('event-stream');
        if (stream) {
            stream.scrollTop = 0;
        }
    }
});

// Confirm destructive actions.
document.addEventListener('htmx:confirm', function(event) {
    if (!event.detail.question) return;
    event.preventDefault();
    if (confirm(event.detail.question)) {
        event.detail.issueRequest();
    }
});

// Refresh dashboard stats every 30 seconds.
(function() {
    var dashboard = document.querySelector('[hx-get="/"]');
    if (dashboard && window.location.pathname === '/') {
        setInterval(function() {
            htmx.ajax('GET', '/', { target: '#main-content', swap: 'innerHTML' });
        }, 30000);
    }
})();

// Update page title with pending action count.
document.addEventListener('htmx:sseMessage', function(event) {
    if (event.detail.type === 'pending_count') {
        var count = parseInt(event.detail.data, 10);
        if (count > 0) {
            document.title = '(' + count + ') Sentinel';
        } else {
            document.title = 'Sentinel';
        }
    }
});
