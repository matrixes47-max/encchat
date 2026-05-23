// encchat language switcher
(function(){
  // APK hide in app
  var ua = navigator.userAgent || '';
  var isApp = ua.indexOf('EncchatApp') !== -1;
  if(isApp){
    var badge = document.getElementById('android-badge');
    var info = document.getElementById('apk-info');
    if(badge) badge.style.display = 'none';
    if(info) info.style.display = 'none';
  }

  // Language switcher
  var lang = localStorage.getItem('encchat_lang') || 'ka';

  function applyLang(l) {
    lang = l;
    localStorage.setItem('encchat_lang', l);

    document.getElementById('btn-ka').classList.toggle('active', l === 'ka');
    document.getElementById('btn-en').classList.toggle('active', l === 'en');
    document.documentElement.lang = l === 'ka' ? 'ka' : 'en';

    document.querySelectorAll('[data-ka][data-en]').forEach(function(el) {
      el.innerHTML = el.getAttribute('data-' + l);
    });

    document.querySelectorAll('[data-ph-ka][data-ph-en]').forEach(function(el) {
      el.placeholder = el.getAttribute('data-ph-' + l);
    });

    document.querySelectorAll('#ttl-select option').forEach(function(opt) {
      var v = opt.getAttribute('data-' + l);
      if(v) opt.textContent = v;
    });

    var dlText = document.getElementById('apk-dl-text');
    if(dlText) dlText.textContent = l === 'ka' ? '▼ ჩამოტვირთვა' : '▼ Download';
  }

  document.getElementById('btn-ka').addEventListener('click', function(){ applyLang('ka'); });
  document.getElementById('btn-en').addEventListener('click', function(){ applyLang('en'); });

  applyLang(lang);
})();
