(() => {
  const tabs = Array.from(document.querySelectorAll('#account-settings [role="tab"]'));
  const selectTab = (tab, focus = false) => {
    tabs.forEach(item => {
      const selected = item === tab;
      item.setAttribute('aria-selected', String(selected));
      item.tabIndex = selected ? 0 : -1;
      document.getElementById(item.getAttribute('aria-controls')).hidden = !selected;
    });
    if (focus) tab.focus();
  };
  tabs.forEach((tab, index) => {
    tab.addEventListener('click', () => selectTab(tab));
    tab.addEventListener('keydown', event => {
      const next = {ArrowRight: (index + 1) % tabs.length, ArrowLeft: (index + tabs.length - 1) % tabs.length, Home: 0, End: tabs.length - 1}[event.key];
      if (next !== undefined) { event.preventDefault(); selectTab(tabs[next], true); }
    });
  });
  if (location.hash === '#oidc') {
    selectTab(document.getElementById('oidc-tab'));
    document.getElementById('account-settings').scrollIntoView({block: 'center'});
  }
  const callback = document.getElementById('OIDCCallback');
  callback.textContent = callback.dataset.configured || location.origin + '/oidc/callback';
  document.getElementById('OIDCRedirectURL').value = callback.textContent;
  const changedAdvanced = new Set();
  const advancedKeys = ['Scopes', 'RedirectURL', 'AutoLogin'];
  const advancedValue = key => {
    const field = document.getElementById('OIDC' + key);
    if (key === 'AutoLogin') return field.checked;
    return field.value.trim();
  };
  advancedKeys.forEach(key => {
    document.getElementById('OIDC' + key).addEventListener('input', () => changedAdvanced.add(key));
  });
  document.getElementById('formGlobal').addEventListener('submit', event => {
    event.preventDefault();
    document.querySelector('.submit_btn').click();
  });
  document.getElementById('oidc-panel').addEventListener('keydown', event => {
    if (event.key === 'Enter' && !event.isComposing && event.target.matches('input:not([type=checkbox])')) {
      event.preventDefault();
      document.getElementById('saveOIDC').click();
    }
  });
  document.getElementById('saveOIDC').addEventListener('click', async event => {
    const button = event.currentTarget;
    if (button.disabled) return;
    const status = document.getElementById('oidcStatus');
    const data = {Enabled: document.getElementById('OIDCEnabled').checked};
    for (const key of ['Issuer', 'ClientID', 'ClientSecret']) data[key] = document.getElementById('OIDC' + key).value;
    if (!callback.dataset.configured) data.RedirectURL = callback.textContent;
    changedAdvanced.forEach(key => { data[key] = advancedValue(key); });
    button.disabled = true;
    const fields = Array.from(document.querySelectorAll('#oidc-panel input'));
    const previousDisabled = fields.map(field => field.disabled);
    fields.forEach(field => { field.disabled = true; });
    status.textContent = '';
    try {
      const response = await fetch('/oidc-settings/save', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(data)});
      if (response.redirected || response.status === 401) throw new Error(i18n('OIDC session expired'));
      if (!response.ok) throw new Error(await response.text());
      await response.json();
      document.getElementById('OIDCClientSecret').value = '';
      if (data.RedirectURL !== undefined) callback.textContent = data.RedirectURL;
      callback.dataset.configured = callback.textContent;
      changedAdvanced.clear();
      status.textContent = i18n('OIDC saved');
    } catch (error) { status.textContent = error.message; }
    finally {
      fields.forEach((field, index) => { field.disabled = previousDisabled[index]; });
      button.disabled = false;
    }
  });
})();
