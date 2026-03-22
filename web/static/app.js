/**
 * Hemmins S3 Admin UI - Minimal JavaScript
 * 
 * Uses vanilla JS to call the existing JSON API endpoints.
 * Session cookie is HttpOnly, so auth state is determined via /ui/api/session/me.
 */
(function() {
  'use strict';

  // DOM Elements
  const app = {
    setupRequired: document.getElementById('setup-required'),
    loginScreen: document.getElementById('login-screen'),
    mainScreen: document.getElementById('main-screen'),
    loadingOverlay: document.getElementById('loading-overlay'),
    
    // Login
    loginForm: document.getElementById('login-form'),
    usernameInput: document.getElementById('username'),
    passwordInput: document.getElementById('password'),
    loginError: document.getElementById('login-error'),
    loginBtn: document.getElementById('login-btn'),
    
    // Main screen
    userInfo: document.getElementById('user-info'),
    logoutBtn: document.getElementById('logout-btn'),
    
    // Stats
    statBuckets: document.getElementById('stat-buckets'),
    statObjects: document.getElementById('stat-objects'),
    statSize: document.getElementById('stat-size'),
    statMultipart: document.getElementById('stat-multipart'),
    
    // Buckets
    bucketsLoading: document.getElementById('buckets-loading'),
    bucketsEmpty: document.getElementById('buckets-empty'),
    bucketsTable: document.getElementById('buckets-table'),
    bucketsTbody: document.getElementById('buckets-tbody'),
    bucketCreateForm: document.getElementById('bucket-create-form'),
    bucketNameInput: document.getElementById('bucket-name-input'),
    bucketCreateBtn: document.getElementById('bucket-create-btn'),
    bucketsError: document.getElementById('buckets-error'),
    bucketsSuccess: document.getElementById('buckets-success'),
    
    // Objects
    objectBucketSelect: document.getElementById('object-bucket-select'),
    objectPrefixInput: document.getElementById('object-prefix-input'),
    objectDelimiterInput: document.getElementById('object-delimiter-input'),
    objectSearchBtn: document.getElementById('object-search-btn'),
    objectBreadcrumb: document.getElementById('object-breadcrumb'),
    objectsError: document.getElementById('objects-error'),
    objectsLoading: document.getElementById('objects-loading'),
    objectsEmpty: document.getElementById('objects-empty'),
    objectsNoBucket: document.getElementById('objects-no-bucket'),
    objectsTable: document.getElementById('objects-table'),
    objectsTbody: document.getElementById('objects-tbody'),
    objectsPagination: document.getElementById('objects-pagination'),
    objectsCount: document.getElementById('objects-count'),
    objectsLoadMore: document.getElementById('objects-load-more'),
    objectMetaPanel: document.getElementById('object-meta-panel'),
    objectMetaClose: document.getElementById('object-meta-close'),
    
    // Navigation
    navBtns: document.querySelectorAll('.nav-btn'),
    sections: {
      dashboard: document.getElementById('section-dashboard'),
      buckets: document.getElementById('section-buckets'),
      objects: document.getElementById('section-objects'),
      'access-keys': document.getElementById('section-access-keys'),
      settings: document.getElementById('section-settings')
    }
  };

  let currentUser = null;
  let csrfToken = null;
  
  // Object browser state
  let objectsState = {
    bucket: '',
    prefix: '',
    delimiter: '/',
    continuationToken: '',
    objects: [],
    commonPrefixes: []
  };

  // ========== API Helpers ==========

  async function fetchCSRF() {
    const res = await fetch('/ui/api/session/csrf');
    if (!res.ok) {
      if (res.status === 503) {
        const data = await res.json();
        throw new Error(data.error || 'setup required');
      }
      throw new Error('Failed to get CSRF token');
    }
    const data = await res.json();
    csrfToken = data.token;
    return csrfToken;
  }

  async function apiCall(method, url, body = null) {
    const headers = {
      'Content-Type': 'application/json'
    };
    
    // Add CSRF token for state-changing requests
    if (method !== 'GET') {
      if (!csrfToken) {
        await fetchCSRF();
      }
      headers['X-CSRF-Token'] = csrfToken;
    }
    
    const options = { method, headers };
    if (body) {
      options.body = JSON.stringify(body);
    }
    
    const res = await fetch(url, options);
    
    // Handle 503 specially for setup-required
    if (res.status === 503) {
      const data = await res.json();
      if (data.error === 'setup required') {
        showScreen('setup');
        throw new Error('setup required');
      }
    }
    
    return res;
  }

  // ========== UI Helpers ==========

  function showScreen(screen) {
    app.setupRequired.style.display = screen === 'setup' ? 'block' : 'none';
    app.loginScreen.style.display = screen === 'login' ? 'block' : 'none';
    app.mainScreen.style.display = screen === 'main' ? 'block' : 'none';
  }

  function showLoading(show) {
    app.loadingOverlay.classList.toggle('hidden', !show);
  }

  function showLoginError(message) {
    app.loginError.textContent = message;
    app.loginError.style.display = message ? 'block' : 'none';
  }

  function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  function formatDate(isoString) {
    const date = new Date(isoString);
    return date.toLocaleDateString('ko-KR', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit'
    });
  }

  function showSection(sectionName) {
    // Update nav
    app.navBtns.forEach(btn => {
      btn.classList.toggle('active', btn.dataset.section === sectionName);
    });
    
    // Show section
    Object.keys(app.sections).forEach(name => {
      if (app.sections[name]) {
        app.sections[name].style.display = name === sectionName ? 'block' : 'none';
      }
    });
    
    // Load section data
    if (sectionName === 'dashboard') {
      loadDashboard();
    } else if (sectionName === 'buckets') {
      loadBuckets();
    } else if (sectionName === 'objects') {
      loadObjectBuckets();
    }
  }

  // ========== Authentication ==========

  async function checkAuth() {
    showLoading(true);
    try {
      const res = await apiCall('GET', '/ui/api/session/me');
      if (res.ok) {
        const data = await res.json();
        currentUser = data;
        app.userInfo.textContent = `${data.username} (${data.role})`;
        showScreen('main');
        showSection('dashboard');
      } else {
        showScreen('login');
      }
    } catch (e) {
      if (e.message !== 'setup required') {
        showScreen('login');
      }
    } finally {
      showLoading(false);
    }
  }

  async function login(username, password) {
    showLoginError('');
    app.loginBtn.disabled = true;
    app.loginBtn.textContent = '로그인 중...';
    
    try {
      await fetchCSRF();
      const res = await apiCall('POST', '/ui/api/session/login', { username, password });
      
      if (res.ok) {
        const data = await res.json();
        currentUser = data;
        app.userInfo.textContent = `${data.username} (${data.role})`;
        showScreen('main');
        showSection('dashboard');
        
        // Clear form
        app.usernameInput.value = '';
        app.passwordInput.value = '';
      } else {
        const data = await res.json();
        showLoginError(data.error || '로그인에 실패했습니다.');
      }
    } catch (e) {
      if (e.message !== 'setup required') {
        showLoginError('서버 연결 오류가 발생했습니다.');
      }
    } finally {
      app.loginBtn.disabled = false;
      app.loginBtn.textContent = '로그인';
    }
  }

  async function logout() {
    showLoading(true);
    try {
      await apiCall('POST', '/ui/api/session/logout');
    } catch (e) {
      // Ignore errors during logout
    } finally {
      currentUser = null;
      csrfToken = null;
      showScreen('login');
      showLoading(false);
    }
  }

  // ========== Dashboard ==========

  async function loadDashboard() {
    try {
      const res = await apiCall('GET', '/ui/api/dashboard');
      if (res.ok) {
        const data = await res.json();
        app.statBuckets.textContent = data.totalBuckets.toLocaleString();
        app.statObjects.textContent = data.totalObjects.toLocaleString();
        app.statSize.textContent = formatBytes(data.totalBytes);
        app.statMultipart.textContent = data.activeMultipartUploads.toLocaleString();
      } else if (res.status === 401) {
        showScreen('login');
      }
    } catch (e) {
      console.error('Failed to load dashboard:', e);
    }
  }

  // ========== Buckets ==========

  function showBucketsMessage(type, message) {
    app.bucketsError.style.display = 'none';
    app.bucketsSuccess.style.display = 'none';
    
    if (type === 'error') {
      app.bucketsError.textContent = message;
      app.bucketsError.style.display = 'block';
    } else if (type === 'success') {
      app.bucketsSuccess.textContent = message;
      app.bucketsSuccess.style.display = 'block';
      // Auto-hide success messages after 3 seconds
      setTimeout(() => {
        app.bucketsSuccess.style.display = 'none';
      }, 3000);
    }
  }

  function hideBucketsMessages() {
    app.bucketsError.style.display = 'none';
    app.bucketsSuccess.style.display = 'none';
  }

  async function loadBuckets() {
    app.bucketsLoading.style.display = 'block';
    app.bucketsEmpty.style.display = 'none';
    app.bucketsTable.style.display = 'none';
    hideBucketsMessages();
    
    try {
      const res = await apiCall('GET', '/ui/api/buckets');
      if (res.ok) {
        const buckets = await res.json();
        
        if (buckets.length === 0) {
          app.bucketsEmpty.style.display = 'block';
        } else {
          app.bucketsTbody.innerHTML = buckets.map(bucket => `
            <tr>
              <td>${escapeHtml(bucket.name)}</td>
              <td>${formatDate(bucket.creationDate)}</td>
              <td class="actions-col">
                <button class="btn-danger btn-small" onclick="window.deleteBucket('${escapeHtml(bucket.name)}')">삭제</button>
              </td>
            </tr>
          `).join('');
          app.bucketsTable.style.display = 'table';
        }
      } else if (res.status === 401) {
        showScreen('login');
      } else {
        const data = await res.json();
        showBucketsMessage('error', data.error || '버킷 목록을 불러오는데 실패했습니다.');
      }
    } catch (e) {
      console.error('Failed to load buckets:', e);
      showBucketsMessage('error', '버킷 목록을 불러오는데 실패했습니다.');
    } finally {
      app.bucketsLoading.style.display = 'none';
    }
  }

  async function createBucket(name) {
    hideBucketsMessages();
    app.bucketCreateBtn.disabled = true;
    app.bucketCreateBtn.textContent = '생성 중...';
    
    try {
      const res = await apiCall('POST', '/ui/api/buckets', { name });
      
      if (res.ok) {
        showBucketsMessage('success', `버킷 '${name}'이(가) 생성되었습니다.`);
        app.bucketNameInput.value = '';
        loadBuckets(); // Refresh the list
      } else {
        const data = await res.json();
        let errorMsg = data.error || '버킷 생성에 실패했습니다.';
        // Map common errors to user-friendly messages
        if (data.error === 'bucket already exists') {
          errorMsg = `버킷 '${name}'이(가) 이미 존재합니다.`;
        } else if (data.error === 'invalid bucket name') {
          errorMsg = '유효하지 않은 버킷 이름입니다. 3-63자의 소문자, 숫자, 하이픈만 사용 가능합니다.';
        } else if (data.error === 'bucket name is required') {
          errorMsg = '버킷 이름을 입력해 주세요.';
        }
        showBucketsMessage('error', errorMsg);
      }
    } catch (e) {
      if (e.message !== 'setup required') {
        console.error('Failed to create bucket:', e);
        showBucketsMessage('error', '서버 연결 오류가 발생했습니다.');
      }
    } finally {
      app.bucketCreateBtn.disabled = false;
      app.bucketCreateBtn.textContent = '버킷 생성';
    }
  }

  async function deleteBucket(name) {
    // Confirmation dialog
    if (!confirm(`버킷 '${name}'을(를) 삭제하시겠습니까?\n\n이 작업은 되돌릴 수 없습니다.`)) {
      return;
    }
    
    hideBucketsMessages();
    
    try {
      const res = await apiCall('DELETE', `/ui/api/buckets/${encodeURIComponent(name)}`);
      
      if (res.ok || res.status === 204) {
        showBucketsMessage('success', `버킷 '${name}'이(가) 삭제되었습니다.`);
        loadBuckets(); // Refresh the list
      } else {
        const data = await res.json();
        let errorMsg = data.error || '버킷 삭제에 실패했습니다.';
        // Map common errors to user-friendly messages
        if (data.error === 'bucket not empty') {
          errorMsg = `버킷 '${name}'이(가) 비어있지 않습니다. 버킷을 삭제하려면 먼저 모든 오브젝트를 삭제해 주세요.`;
        } else if (data.error === 'bucket not found') {
          errorMsg = `버킷 '${name}'을(를) 찾을 수 없습니다.`;
        }
        showBucketsMessage('error', errorMsg);
      }
    } catch (e) {
      if (e.message !== 'setup required') {
        console.error('Failed to delete bucket:', e);
        showBucketsMessage('error', '서버 연결 오류가 발생했습니다.');
      }
    }
  }

  // Expose deleteBucket to window for inline onclick handlers
  window.deleteBucket = deleteBucket;

  // ========== Object Browser ==========

  function showObjectsMessage(type, message) {
    app.objectsError.style.display = 'none';
    
    if (type === 'error') {
      app.objectsError.textContent = message;
      app.objectsError.style.display = 'block';
    }
  }

  function hideObjectsMessage() {
    app.objectsError.style.display = 'none';
  }

  function resetObjectsUI() {
    app.objectsLoading.style.display = 'none';
    app.objectsEmpty.style.display = 'none';
    app.objectsNoBucket.style.display = 'none';
    app.objectsTable.style.display = 'none';
    app.objectsPagination.style.display = 'none';
    app.objectBreadcrumb.style.display = 'none';
    hideObjectsMessage();
    closeObjectMeta();
  }

  async function loadObjectBuckets() {
    // Populate the bucket select dropdown
    try {
      const res = await apiCall('GET', '/ui/api/buckets');
      if (res.ok) {
        const buckets = await res.json();
        const currentValue = app.objectBucketSelect.value;
        
        app.objectBucketSelect.innerHTML = '<option value="">버킷을 선택하세요</option>' +
          buckets.map(bucket => 
            `<option value="${escapeHtml(bucket.name)}">${escapeHtml(bucket.name)}</option>`
          ).join('');
        
        // Restore selection if possible
        if (currentValue && buckets.some(b => b.name === currentValue)) {
          app.objectBucketSelect.value = currentValue;
        }
        
        // If a bucket is selected, load its objects
        if (objectsState.bucket) {
          app.objectBucketSelect.value = objectsState.bucket;
          loadObjects(false);
        } else {
          resetObjectsUI();
          app.objectsNoBucket.style.display = 'block';
        }
      } else if (res.status === 401) {
        showScreen('login');
      }
    } catch (e) {
      console.error('Failed to load buckets for object browser:', e);
    }
  }

  async function loadObjects(append = false) {
    const bucket = app.objectBucketSelect.value;
    if (!bucket) {
      resetObjectsUI();
      app.objectsNoBucket.style.display = 'block';
      return;
    }
    
    if (!append) {
      resetObjectsUI();
      objectsState.bucket = bucket;
      objectsState.prefix = app.objectPrefixInput.value;
      objectsState.delimiter = app.objectDelimiterInput.value;
      objectsState.continuationToken = '';
      objectsState.objects = [];
      objectsState.commonPrefixes = [];
    }
    
    app.objectsLoading.style.display = 'block';
    hideObjectsMessage();
    
    // Build URL
    let url = `/ui/api/buckets/${encodeURIComponent(bucket)}/objects?`;
    const params = [];
    if (objectsState.prefix) {
      params.push(`prefix=${encodeURIComponent(objectsState.prefix)}`);
    }
    if (objectsState.delimiter) {
      params.push(`delimiter=${encodeURIComponent(objectsState.delimiter)}`);
    }
    if (objectsState.continuationToken) {
      params.push(`continuation-token=${encodeURIComponent(objectsState.continuationToken)}`);
    }
    url += params.join('&');
    
    try {
      const res = await apiCall('GET', url);
      if (res.ok) {
        const data = await res.json();
        
        // Append to existing state
        if (data.commonPrefixes) {
          objectsState.commonPrefixes = append ? 
            objectsState.commonPrefixes.concat(data.commonPrefixes) : 
            data.commonPrefixes;
        }
        if (data.objects) {
          objectsState.objects = append ? 
            objectsState.objects.concat(data.objects) : 
            data.objects;
        }
        objectsState.continuationToken = data.nextContinuationToken || '';
        
        renderObjectsList(data);
      } else if (res.status === 401) {
        showScreen('login');
      } else {
        const errorData = await res.json();
        showObjectsMessage('error', errorData.error || '오브젝트 목록을 불러오는데 실패했습니다.');
      }
    } catch (e) {
      console.error('Failed to load objects:', e);
      showObjectsMessage('error', '서버 연결 오류가 발생했습니다.');
    } finally {
      app.objectsLoading.style.display = 'none';
    }
  }

  function renderObjectsList(data) {
    // Render breadcrumb
    renderBreadcrumb();
    
    const allItems = objectsState.commonPrefixes.length + objectsState.objects.length;
    
    if (allItems === 0) {
      app.objectsEmpty.style.display = 'block';
      return;
    }
    
    // Build table rows
    const rows = [];
    
    // Common prefixes (folders) first
    objectsState.commonPrefixes.forEach(prefix => {
      const displayName = getDisplayName(prefix, objectsState.prefix);
      rows.push(`
        <tr class="folder-row" data-prefix="${escapeHtml(prefix)}">
          <td>
            <span class="folder-icon">📁</span>
            <a href="#" class="folder-link" onclick="window.navigateToPrefix('${escapeHtml(prefix)}'); return false;">${escapeHtml(displayName)}</a>
          </td>
          <td>-</td>
          <td>-</td>
          <td class="actions-col">-</td>
        </tr>
      `);
    });
    
    // Objects
    objectsState.objects.forEach(obj => {
      const displayName = getDisplayName(obj.key, objectsState.prefix);
      rows.push(`
        <tr class="object-row" data-key="${escapeHtml(obj.key)}">
          <td>
            <span class="file-icon">📄</span>
            ${escapeHtml(displayName)}
          </td>
          <td>${formatBytes(obj.size)}</td>
          <td>${formatDate(obj.lastModified)}</td>
          <td class="actions-col">
            <button class="btn-small" onclick="window.showObjectMeta('${escapeHtml(objectsState.bucket)}', '${escapeHtml(obj.key)}')">정보</button>
            <button class="btn-small btn-primary" onclick="window.downloadObject('${escapeHtml(objectsState.bucket)}', '${escapeHtml(obj.key)}')">다운로드</button>
          </td>
        </tr>
      `);
    });
    
    app.objectsTbody.innerHTML = rows.join('');
    app.objectsTable.style.display = 'table';
    
    // Pagination
    app.objectsCount.textContent = `${allItems}개 항목`;
    if (objectsState.continuationToken) {
      app.objectsPagination.style.display = 'flex';
      app.objectsLoadMore.style.display = 'inline-block';
    } else {
      app.objectsPagination.style.display = 'flex';
      app.objectsLoadMore.style.display = 'none';
    }
  }

  function renderBreadcrumb() {
    if (!objectsState.prefix) {
      app.objectBreadcrumb.style.display = 'none';
      return;
    }
    
    const parts = objectsState.prefix.split('/').filter(p => p);
    let html = `<a href="#" onclick="window.navigateToPrefix(''); return false;">🏠 ${escapeHtml(objectsState.bucket)}</a>`;
    
    let currentPath = '';
    parts.forEach((part, index) => {
      currentPath += part + '/';
      if (index === parts.length - 1) {
        html += ` / <span>${escapeHtml(part)}</span>`;
      } else {
        html += ` / <a href="#" onclick="window.navigateToPrefix('${escapeHtml(currentPath)}'); return false;">${escapeHtml(part)}</a>`;
      }
    });
    
    app.objectBreadcrumb.innerHTML = html;
    app.objectBreadcrumb.style.display = 'block';
  }

  function getDisplayName(key, prefix) {
    if (!prefix) return key;
    if (key.startsWith(prefix)) {
      return key.slice(prefix.length);
    }
    return key;
  }

  function navigateToPrefix(prefix) {
    app.objectPrefixInput.value = prefix;
    objectsState.prefix = prefix;
    objectsState.continuationToken = '';
    loadObjects(false);
  }
  window.navigateToPrefix = navigateToPrefix;

  async function showObjectMeta(bucket, key) {
    hideObjectsMessage();
    
    try {
      const url = `/ui/api/buckets/${encodeURIComponent(bucket)}/objects/meta?key=${encodeURIComponent(key)}`;
      const res = await apiCall('GET', url);
      
      if (res.ok) {
        const meta = await res.json();
        
        // Populate meta panel
        document.getElementById('meta-bucket').textContent = meta.bucket;
        document.getElementById('meta-key').textContent = meta.key;
        document.getElementById('meta-size').textContent = formatBytes(meta.size);
        document.getElementById('meta-content-type').textContent = meta.contentType;
        document.getElementById('meta-etag').textContent = meta.etag;
        document.getElementById('meta-last-modified').textContent = formatDate(meta.lastModified);
        document.getElementById('meta-storage-class').textContent = meta.storageClass;
        
        // User metadata
        const userMetaSection = document.getElementById('meta-user-metadata');
        const userMetaContent = document.getElementById('meta-user-metadata-content');
        if (meta.userMetadata && Object.keys(meta.userMetadata).length > 0) {
          userMetaContent.innerHTML = Object.entries(meta.userMetadata)
            .map(([k, v]) => `<div class="meta-user-item"><strong>${escapeHtml(k)}:</strong> ${escapeHtml(v)}</div>`)
            .join('');
          userMetaSection.style.display = 'block';
        } else {
          userMetaSection.style.display = 'none';
        }
        
        app.objectMetaPanel.style.display = 'block';
      } else if (res.status === 401) {
        showScreen('login');
      } else {
        const data = await res.json();
        showObjectsMessage('error', data.error || '메타데이터를 불러오는데 실패했습니다.');
      }
    } catch (e) {
      console.error('Failed to load object metadata:', e);
      showObjectsMessage('error', '서버 연결 오류가 발생했습니다.');
    }
  }
  window.showObjectMeta = showObjectMeta;

  function closeObjectMeta() {
    app.objectMetaPanel.style.display = 'none';
  }

  function downloadObject(bucket, key) {
    // Trigger browser download via the download endpoint
    const url = `/ui/api/buckets/${encodeURIComponent(bucket)}/objects/download?key=${encodeURIComponent(key)}`;
    window.location.href = url;
  }
  window.downloadObject = downloadObject;

  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  // ========== Event Listeners ==========

  app.loginForm.addEventListener('submit', (e) => {
    e.preventDefault();
    login(app.usernameInput.value, app.passwordInput.value);
  });

  app.logoutBtn.addEventListener('click', logout);

  app.navBtns.forEach(btn => {
    if (!btn.disabled) {
      btn.addEventListener('click', () => {
        showSection(btn.dataset.section);
      });
    }
  });

  app.bucketCreateForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const name = app.bucketNameInput.value.trim();
    if (name) {
      createBucket(name);
    }
  });

  // Object browser event listeners
  app.objectBucketSelect.addEventListener('change', () => {
    objectsState.bucket = app.objectBucketSelect.value;
    objectsState.prefix = '';
    app.objectPrefixInput.value = '';
    loadObjects(false);
  });

  app.objectSearchBtn.addEventListener('click', () => {
    loadObjects(false);
  });

  app.objectPrefixInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      loadObjects(false);
    }
  });

  app.objectDelimiterInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      loadObjects(false);
    }
  });

  app.objectsLoadMore.addEventListener('click', () => {
    loadObjects(true);
  });

  app.objectMetaClose.addEventListener('click', closeObjectMeta);

  // ========== Initialize ==========

  checkAuth();

})();
