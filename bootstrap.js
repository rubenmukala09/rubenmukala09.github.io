// Apply saved display preferences before React renders. Keeping this in a
// same-origin file allows a strict script policy without inline execution.
;(function () {
  document.documentElement.setAttribute('data-theme', 'ember')
  try {
    var raw = localStorage.getItem('reset:site_content')
    if (!raw) return
    var prefs = (JSON.parse(raw) || {}).preferences || {}
    if (typeof prefs.siteTitle === 'string' && prefs.siteTitle) {
      document.title = prefs.siteTitle
    }
    if (typeof prefs.seoDescription === 'string' && prefs.seoDescription) {
      var meta = document.querySelector('meta[name="description"]')
      if (meta) meta.setAttribute('content', prefs.seoDescription)
    }
    if (prefs.announcementEnabled && typeof prefs.announcementText === 'string' && prefs.announcementText.trim()) {
      document.documentElement.setAttribute('data-banner', 'on')
    }
  } catch {
    // Missing or blocked browser storage keeps the default theme and copy.
  }
})()
