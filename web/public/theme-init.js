// Sets <html data-theme> before the page paints, so there is no flash of the wrong theme.
// A separate file (not an inline script) because the Content-Security-Policy allows only 'self'.
;(function () {
  var stored = null
  try {
    stored = window.localStorage.getItem('qrguard-theme')
  } catch (e) {
    // storage blocked (private mode): follow the OS
  }
  var theme =
    stored === 'light' || stored === 'dark'
      ? stored
      : window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches
        ? 'dark'
        : 'light'
  document.documentElement.setAttribute('data-theme', theme)
})()
