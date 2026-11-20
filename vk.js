// Вход через VK ID (OAuth 2.1, code + PKCE). Ключ доступа нигде не хранится: после входа показываем имя и сразу отзываем ключ.
var ZEDDD_VK = (function () {
  var APP = 54902302, REDIRECT = 'https://zeddd-app.github.io/vk/', KEY = 'zeddd_vk_pkce';

  function b64url(bytes) {
    return btoa(String.fromCharCode.apply(null, new Uint8Array(bytes))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function rand(n) { var a = new Uint8Array(n); crypto.getRandomValues(a); return b64url(a); }

  function login() {
    var verifier = rand(48), state = rand(24);
    return crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)).then(function (h) {
      try { sessionStorage.setItem(KEY, JSON.stringify({ v: verifier, s: state })); } catch (e) { throw new Error('sessionStorage недоступен'); }
      location.href = 'https://id.vk.com/authorize?' + new URLSearchParams({
        response_type: 'code', client_id: APP, redirect_uri: REDIRECT, state: state,
        code_challenge: b64url(h), code_challenge_method: 'S256', scope: 'vkid.personal_info'
      });
    });
  }

  // На странице /vk/: обменять code на ключ, получить имя, отозвать ключ.
  function finish(VKID) {
    var q = new URLSearchParams(location.search), saved = null;
    try { saved = JSON.parse(sessionStorage.getItem(KEY) || 'null'); sessionStorage.removeItem(KEY); } catch (e) {}
    if (!q.get('code')) return Promise.resolve(null);
    if (!saved || saved.s !== q.get('state')) return Promise.reject(new Error('state не совпал'));
    VKID.Config.init({ app: APP, redirectUrl: REDIRECT, state: saved.s, codeVerifier: saved.v, scope: 'vkid.personal_info' });
    return VKID.Auth.exchangeCode(q.get('code'), q.get('device_id'), saved.v).then(function (t) {
      return VKID.Auth.userInfo(t.access_token).then(function (r) {
        return VKID.Auth.logout(t.access_token).catch(function () {}).then(function () { return r.user || {}; });
      });
    });
  }

  return { login: login, finish: finish };
})();
