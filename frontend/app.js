(() => {
  const $ = (id) => document.getElementById(id);

  let token = sessionStorage.getItem('trustvault_token') || '';
  let currentUser = null;
  let documents = [];

  const setMessage = (id, text, type = '') => {
    const el = $(id);
    if (!el) return;
    el.textContent = text;
    el.className = `message ${type}`;
  };

  const toast = (text) => {
    const el = $('toast');
    if (!el) return;
    el.textContent = text;
    el.classList.add('show');
    setTimeout(() => el.classList.remove('show'), 2600);
  };

  const api = async (path, options = {}) => {
    const headers = new Headers(options.headers || {});

    if (token) {
      headers.set('Authorization', `Bearer ${token}`);
    }

    if (
      options.body &&
      !(options.body instanceof FormData) &&
      !headers.has('Content-Type')
    ) {
      headers.set('Content-Type', 'application/json');
    }

    const response = await fetch(path, {
      ...options,
      headers
    });

    const type = response.headers.get('content-type') || '';
    let body;

    if (type.includes('application/json')) {
      body = await response.json();
    } else {
      body = await response.blob();
    }

    if (!response.ok) {
      throw new Error(body?.detail || `Request failed (${response.status})`);
    }

    return { response, body };
  };

  const showAuth = () => {
    $('authView').classList.remove('hidden');
    $('appView').classList.add('hidden');
    $('logoutBtn').classList.add('hidden');
    $('whoami').textContent = 'Not signed in';
  };

  const showApp = async () => {
    try {
      const { body } = await api('/auth/me');
      currentUser = body;

      $('authView').classList.add('hidden');
      $('appView').classList.remove('hidden');
      $('logoutBtn').classList.remove('hidden');

      $('whoami').textContent = `${body.username} · ${body.role}`;
      $('roleLabel').textContent = body.role.toUpperCase();

      $('adminPanel').classList.toggle(
        'hidden',
        body.role !== 'admin'
      );

      await loadDocuments();
    } catch (error) {
      token = '';
      sessionStorage.removeItem('trustvault_token');
      showAuth();
      setMessage('authMessage', error.message, 'error');
    }
  };

  // Login and registration tab switching
  document.querySelectorAll('[data-tab]').forEach((button) => {
    button.addEventListener('click', () => {
      document.querySelectorAll('[data-tab]').forEach((b) => {
        b.classList.toggle('active', b === button);
      });

      $('loginForm').classList.toggle(
        'hidden',
        button.dataset.tab !== 'login'
      );

      $('registerForm').classList.toggle(
        'hidden',
        button.dataset.tab !== 'register'
      );

      setMessage('authMessage', '');
    });
  });

  // SIGN IN
  $('loginForm').addEventListener('submit', async (event) => {
    event.preventDefault();

    const loginForm = event.currentTarget;
    const form = new FormData(loginForm);

    const username = form.get('username');
    const password = form.get('password');

    setMessage('authMessage', 'Signing in…');

    try {
      const response = await fetch('/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({
          username: username,
          password: password
        })
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || 'Sign in failed');
      }

      if (!data.access_token) {
        throw new Error('Login succeeded but no access token was returned.');
      }

      token = data.access_token;
      sessionStorage.setItem('trustvault_token', token);

      await showApp();
    } catch (error) {
      setMessage('authMessage', error.message, 'error');
    }
  });

  // REGISTER
  $('registerForm').addEventListener('submit', async (event) => {
    event.preventDefault();

    const registerForm = event.currentTarget;
    const form = new FormData(registerForm);

    setMessage('authMessage', 'Creating account…');

    try {
      await api('/auth/register', {
        method: 'POST',
        body: JSON.stringify({
          username: form.get('username'),
          email: form.get('email'),
          password: form.get('password')
        })
      });

      setMessage(
        'authMessage',
        'Account created. Sign in with your new credentials.',
        'success'
      );

      document.querySelector('[data-tab="login"]').click();
      $('loginForm').elements.username.value = form.get('username');
    } catch (error) {
      setMessage('authMessage', error.message, 'error');
    }
  });

  // SIGN OUT
  $('logoutBtn').addEventListener('click', () => {
    token = '';
    currentUser = null;

    sessionStorage.removeItem('trustvault_token');

    showAuth();
    toast('Signed out');
  });

  // DOCUMENT UPLOAD
  $('uploadForm').addEventListener('submit', async (event) => {
    event.preventDefault();

    // Capture the form before awaiting the API request.
    const uploadForm = event.currentTarget;
    const formData = new FormData(uploadForm);

    const category =
      formData.get('category') || 'uncategorized';

    setMessage('uploadMessage', 'Uploading…');

    try {
      await api(
        `/documents/upload?category=${encodeURIComponent(category)}`,
        {
          method: 'POST',
          body: formData
        }
      );

      uploadForm.reset();

      const categoryField =
        uploadForm.querySelector('[name="category"]');

      if (categoryField) {
        categoryField.value = 'uncategorized';
      }

      setMessage(
        'uploadMessage',
        'Upload completed and recorded in the audit trail.',
        'success'
      );

      await loadDocuments();
      toast('Document uploaded');
    } catch (error) {
      setMessage('uploadMessage', error.message, 'error');
    }
  });

  // SEARCH AND REFRESH
  $('refreshBtn').addEventListener('click', loadDocuments);
  $('searchBtn').addEventListener('click', loadDocuments);

  $('searchInput').addEventListener('keydown', (event) => {
    if (event.key === 'Enter') loadDocuments();
  });

  $('categoryFilter').addEventListener('keydown', (event) => {
    if (event.key === 'Enter') loadDocuments();
  });

  // LOAD DOCUMENTS
  async function loadDocuments() {
    if (!token) return;

    $('documentList').innerHTML =
      '<div class="empty-state">Loading documents…</div>';

    const params = new URLSearchParams();

    const search = $('searchInput').value.trim();
    const category = $('categoryFilter').value.trim();

    if (search) params.set('search', search);
    if (category) params.set('category', category);

    try {
      const { body } = await api(
        `/documents${params.size ? `?${params}` : ''}`
      );

      documents = body;
      renderDocuments(body);

      $('docCount').textContent = body.length;
      $('visibleCount').textContent =
        `${body.length} file${body.length === 1 ? '' : 's'}`;

      setMessage('listMessage', '');
    } catch (error) {
      $('documentList').innerHTML = '';
      setMessage('listMessage', error.message, 'error');
    }
  }

  // RENDER DOCUMENT LIST
  function renderDocuments(items) {
    const host = $('documentList');
    host.replaceChildren();

    if (!items.length) {
      host.innerHTML =
        '<div class="empty-state">No documents match your search yet.</div>';
      return;
    }

    for (const doc of items) {
      const row = document.createElement('div');
      row.className = 'doc-row';

      const ext = (
        doc.filename.split('.').pop() || 'FILE'
      ).toUpperCase().slice(0, 4);

      const icon = document.createElement('div');
      icon.className = 'file-icon';
      icon.textContent = ext;

      const main = document.createElement('div');
      main.className = 'doc-main';

      const name = document.createElement('div');
      name.className = 'doc-name';
      name.textContent = doc.filename;

      const meta = document.createElement('div');
      meta.className = 'doc-meta';

      meta.textContent =
        `${doc.category} · ${
          doc.access === 'OWNER'
            ? 'Owner'
            : `${doc.access} shared access`
        } · ${
          doc.created_at
            ? new Date(doc.created_at).toLocaleDateString()
            : ''
        }`;

      main.append(name, meta);

      const actions = document.createElement('div');
      actions.className = 'doc-actions';

      actions.append(
        makeButton('Download', () =>
          downloadDocument(doc.id, doc.filename)
        )
      );

      if (doc.access === 'OWNER' || doc.access === 'EDIT') {
        actions.append(
          makeButton('Rename / category', () => editMetadata(doc))
        );
      }

      if (doc.access === 'OWNER') {
        actions.append(
          makeButton('Share', () => shareDocument(doc.id)),
          makeButton('Permissions', () => managePermissions(doc.id)),
          makeButton('Delete', () => deleteDocument(doc.id), true)
        );
      }

      row.append(icon, main, actions);
      host.append(row);
    }
  }

  function makeButton(text, action, danger = false) {
    const button = document.createElement('button');

    button.type = 'button';
    button.className = `mini-btn${danger ? ' danger' : ''}`;
    button.textContent = text;
    button.addEventListener('click', action);

    return button;
  }

  // DOWNLOAD DOCUMENT
  async function downloadDocument(id, filename) {
    try {
      const { body } = await api(`/documents/${id}/download`);

      const url = URL.createObjectURL(body);
      const link = document.createElement('a');

      link.href = url;
      link.download = filename;

      document.body.append(link);
      link.click();
      link.remove();

      setTimeout(() => URL.revokeObjectURL(url), 1000);

      toast('Download requested');
    } catch (error) {
      toast(error.message);
    }
  }

  // UPDATE DOCUMENT DETAILS
  async function editMetadata(doc) {
    const filename = prompt(
      'Document display name:',
      doc.filename
    );

    if (filename === null) return;

    const category = prompt('Category:', doc.category);

    if (category === null) return;

    try {
      await api(`/documents/${doc.id}/metadata`, {
        method: 'PATCH',
        body: JSON.stringify({ filename, category })
      });

      toast('Document details updated');
      await loadDocuments();
    } catch (error) {
      toast(error.message);
    }
  }

  // SHARE DOCUMENT
  async function shareDocument(id) {
    const userId = prompt(
      'Enter the recipient user ID (ask them to register first):'
    );

    if (userId === null) return;

    if (!/^\d+$/.test(userId)) {
      toast('Enter a numeric user ID');
      return;
    }

    const permission = prompt('Type READ or EDIT:', 'READ');

    if (permission === null) return;

    const normalizedPermission = permission.trim().toUpperCase();

    if (!['READ', 'EDIT'].includes(normalizedPermission)) {
      toast('Permission must be READ or EDIT');
      return;
    }

    try {
      await api(`/documents/${id}/permissions`, {
        method: 'POST',
        body: JSON.stringify({
          user_id: Number(userId),
          permission: normalizedPermission
        })
      });

      toast('Permission saved');
      await loadDocuments();
    } catch (error) {
      toast(error.message);
    }
  }

  // VIEW AND REVOKE PERMISSIONS
  async function managePermissions(id) {
    try {
      const { body } = await api(
        `/documents/${id}/permissions`
      );

      if (!body.length) {
        toast('No active shares for this document');
        return;
      }

      const summary = body
        .map(
          (row) =>
            `User ID ${row.user_id} (${row.username}) — ${row.permission}`
        )
        .join('\n');

      const choice = prompt(
        `Current permissions:\n${summary}\n\n` +
        'Enter the USER ID to revoke, or Cancel to keep all permissions:'
      );

      if (choice === null || !choice.trim()) return;

      if (!/^\d+$/.test(choice.trim())) {
        toast('Enter a numeric user ID');
        return;
      }

      const selectedId = Number(choice.trim());

      if (!body.some((row) => row.user_id === selectedId)) {
        toast('That user does not have a permission on this document');
        return;
      }

      if (!confirm(`Revoke access for user ID ${selectedId}?`)) {
        return;
      }

      await api(
        `/documents/${id}/permissions/${selectedId}`,
        { method: 'DELETE' }
      );

      toast('Permission revoked');
      await loadDocuments();
    } catch (error) {
      toast(error.message);
    }
  }

  // DELETE DOCUMENT
  async function deleteDocument(id) {
    if (
      !confirm(
        'Delete this document and its stored file? Past audit events are retained.'
      )
    ) {
      return;
    }

    try {
      await api(`/documents/${id}`, {
        method: 'DELETE'
      });

      toast('Document deleted');
      await loadDocuments();
    } catch (error) {
      toast(error.message);
    }
  }

  // ADMIN: LOAD AUDIT LOGS
  $('loadAuditBtn').addEventListener('click', async () => {
    try {
      const { body } = await api('/admin/audit-logs');

      const table = document.createElement('table');

      table.innerHTML =
        '<thead><tr>' +
        '<th>ID</th><th>User</th><th>Document</th>' +
        '<th>Action</th><th>Outcome</th><th>Details</th>' +
        '</tr></thead>';

      const tbody = document.createElement('tbody');

      body.slice(0, 100).forEach((log) => {
        const tr = document.createElement('tr');

        [
          log.id,
          log.user_id ?? '—',
          log.document_id ?? '—',
          log.action,
          log.outcome,
          log.details
        ].forEach((value) => {
          const td = document.createElement('td');
          td.textContent = value;
          tr.append(td);
        });

        tbody.append(tr);
      });

      table.append(tbody);
      $('auditResults').replaceChildren(table);

      setMessage(
        'auditMessage',
        `Showing ${Math.min(body.length, 100)} of ${body.length} audit events.`,
        'success'
      );
    } catch (error) {
      setMessage('auditMessage', error.message, 'error');
    }
  });

  // ADMIN: VERIFY AUDIT LOG INTEGRITY
  $('verifyAuditBtn').addEventListener('click', async () => {
    try {
      const { body } = await api('/admin/audit-logs/verify');

      setMessage(
        'auditMessage',
        `${body.message}.`,
        body.valid ? 'success' : 'error'
      );
    } catch (error) {
      setMessage('auditMessage', error.message, 'error');
    }
  });

  // RESTORE SESSION IF A TOKEN EXISTS
  if (token) {
    showApp();
  } else {
    showAuth();
  }
})();