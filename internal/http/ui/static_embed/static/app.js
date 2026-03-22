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
    objectsSuccess: document.getElementById('objects-success'),
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
    
    // Object Upload
    objectUploadSection: document.getElementById('object-upload-section'),
    objectUploadForm: document.getElementById('object-upload-form'),
    objectKeyInput: document.getElementById('object-key-input'),
    objectFileInput: document.getElementById('object-file-input'),
    objectUploadBtn: document.getElementById('object-upload-btn'),
    
    // Access Keys
    accessKeysLoading: document.getElementById('access-keys-loading'),
    accessKeysEmpty: document.getElementById('access-keys-empty'),
    accessKeysTable: document.getElementById('access-keys-table'),
    accessKeysTbody: document.getElementById('access-keys-tbody'),
    accessKeyCreateForm: document.getElementById('access-key-create-form'),
    accessKeyDescriptionInput: document.getElementById('access-key-description-input'),
    accessKeyCreateBtn: document.getElementById('access-key-create-btn'),
    accessKeysError: document.getElementById('access-keys-error'),
    accessKeysSuccess: document.getElementById('access-keys-success'),
    accessKeySecretDisplay: document.getElementById('access-key-secret-display'),
    newAccessKeyId: document.getElementById('new-access-key-id'),
    newSecretKey: document.getElementById('new-secret-key'),
    secretToggleBtn: document.getElementById('secret-toggle-btn'),
    secretDismissBtn: document.getElementById('secret-dismiss-btn'),
    
    // Settings
    settingsLoading: document.getElementById('settings-loading'),
    settingsError: document.getElementById('settings-error'),
    settingsContent: document.getElementById('settings-content'),
    settingsPathsTbody: document.getElementById('settings-paths-tbody'),
    
    // Password Change
    passwordChangeForm: document.getElementById('password-change-form'),
    currentPasswordInput: document.getElementById('current-password'),
    newPasswordInput: document.getElementById('new-password'),
    passwordChangeBtn: document.getElementById('password-change-btn'),
    passwordChangeError: document.getElementById('password-change-error'),
    passwordChangeSuccess: document.getElementById('password-change-success'),
    
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
    } else if (sectionName === 'access-keys') {
      loadAccessKeys();
    } else if (sectionName === 'settings') {
      loadSettings();
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
            <tr data-bucket-name="${escapeHtml(bucket.name)}">
              <td>${escapeHtml(bucket.name)}</td>
              <td>${formatDate(bucket.creationDate)}</td>
              <td class="actions-col">
                <button class="btn-danger btn-small" data-action="delete-bucket">삭제</button>
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
    app.objectsSuccess.style.display = 'none';
    
    if (type === 'error') {
      app.objectsError.textContent = message;
      app.objectsError.style.display = 'block';
    } else if (type === 'success') {
      app.objectsSuccess.textContent = message;
      app.objectsSuccess.style.display = 'block';
      // Auto-hide success messages after 3 seconds
      setTimeout(() => {
        app.objectsSuccess.style.display = 'none';
      }, 3000);
    }
  }

  function hideObjectsMessage() {
    app.objectsError.style.display = 'none';
    app.objectsSuccess.style.display = 'none';
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
  
  function updateUploadSection() {
    // Show/hide upload section based on bucket selection
    if (objectsState.bucket) {
      app.objectUploadSection.style.display = 'block';
      // Set default key based on current prefix
      if (objectsState.prefix && !app.objectKeyInput.value) {
        app.objectKeyInput.value = objectsState.prefix;
      }
    } else {
      app.objectUploadSection.style.display = 'none';
    }
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
        updateUploadSection();
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
      params.push(`continuationToken=${encodeURIComponent(objectsState.continuationToken)}`);
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
      updateUploadSection();
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
            <a href="#" class="folder-link" data-action="navigate-prefix">${escapeHtml(displayName)}</a>
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
        <tr class="object-row" data-key="${escapeHtml(obj.key)}" data-bucket="${escapeHtml(objectsState.bucket)}">
          <td>
            <span class="file-icon">📄</span>
            ${escapeHtml(displayName)}
          </td>
          <td>${formatBytes(obj.size)}</td>
          <td>${formatDate(obj.lastModified)}</td>
          <td class="actions-col">
            <div class="object-actions">
              <button class="btn-small" data-action="show-meta">정보</button>
              <button class="btn-small btn-primary" data-action="download">다운로드</button>
              <button class="btn-small btn-danger" data-action="delete">삭제</button>
            </div>
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
    let html = `<a href="#" data-breadcrumb-prefix="">🏠 ${escapeHtml(objectsState.bucket)}</a>`;
    
    let currentPath = '';
    parts.forEach((part, index) => {
      currentPath += part + '/';
      if (index === parts.length - 1) {
        html += ` / <span>${escapeHtml(part)}</span>`;
      } else {
        html += ` / <a href="#" data-breadcrumb-prefix="${escapeHtml(currentPath)}">${escapeHtml(part)}</a>`;
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

  async function uploadObject(bucket, key, file) {
    hideObjectsMessage();
    app.objectUploadBtn.disabled = true;
    app.objectUploadBtn.textContent = '업로드 중...';
    
    try {
      // Fetch CSRF token first
      if (!csrfToken) {
        await fetchCSRF();
      }
      
      const url = `/ui/api/buckets/${encodeURIComponent(bucket)}/objects/upload?key=${encodeURIComponent(key)}`;
      const res = await fetch(url, {
        method: 'POST',
        headers: {
          'X-CSRF-Token': csrfToken,
          'Content-Type': file.type || 'application/octet-stream'
        },
        body: file
      });
      
      if (res.ok) {
        showObjectsMessage('success', `'${key}' 업로드 완료`);
        // Clear form
        app.objectKeyInput.value = objectsState.prefix || '';
        app.objectFileInput.value = '';
        // Refresh object list
        loadObjects(false);
      } else if (res.status === 401) {
        showScreen('login');
      } else {
        const data = await res.json();
        let errorMsg = data.error || '업로드에 실패했습니다.';
        if (data.error === 'key parameter is required') {
          errorMsg = '오브젝트 키를 입력해 주세요.';
        } else if (data.error === 'bucket not found') {
          errorMsg = '버킷을 찾을 수 없습니다.';
        } else if (data.error === 'invalid bucket name') {
          errorMsg = '유효하지 않은 버킷 이름입니다.';
        }
        showObjectsMessage('error', errorMsg);
      }
    } catch (e) {
      console.error('Failed to upload object:', e);
      showObjectsMessage('error', '서버 연결 오류가 발생했습니다.');
    } finally {
      app.objectUploadBtn.disabled = false;
      app.objectUploadBtn.textContent = '업로드';
    }
  }
  
  async function deleteObject(bucket, key) {
    // Confirmation dialog
    if (!confirm(`오브젝트 '${key}'를 삭제하시겠습니까?\n\n이 작업은 되돌릴 수 없습니다.`)) {
      return;
    }
    
    hideObjectsMessage();
    
    try {
      const url = `/ui/api/buckets/${encodeURIComponent(bucket)}/objects?key=${encodeURIComponent(key)}`;
      const res = await apiCall('DELETE', url);
      
      if (res.ok || res.status === 204) {
        showObjectsMessage('success', `'${key}' 삭제 완료`);
        // Refresh object list
        loadObjects(false);
      } else if (res.status === 401) {
        showScreen('login');
      } else {
        const data = await res.json();
        let errorMsg = data.error || '삭제에 실패했습니다.';
        if (data.error === 'object not found') {
          errorMsg = `오브젝트 '${key}'를 찾을 수 없습니다.`;
        } else if (data.error === 'bucket not found') {
          errorMsg = '버킷을 찾을 수 없습니다.';
        }
        showObjectsMessage('error', errorMsg);
      }
    } catch (e) {
      console.error('Failed to delete object:', e);
      showObjectsMessage('error', '서버 연결 오류가 발생했습니다.');
    }
  }
  window.deleteObject = deleteObject;

  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  // ========== Settings ==========

  async function loadSettings() {
    app.settingsLoading.style.display = 'block';
    app.settingsError.style.display = 'none';
    app.settingsContent.style.display = 'none';
    
    try {
      const res = await apiCall('GET', '/ui/api/settings');
      if (res.ok) {
        const data = await res.json();
        renderSettings(data);
        app.settingsContent.style.display = 'block';
      } else if (res.status === 401) {
        showScreen('login');
      } else {
        const errData = await res.json();
        showSettingsError(errData.error || '설정을 불러오는데 실패했습니다.');
      }
    } catch (e) {
      console.error('Failed to load settings:', e);
      showSettingsError('서버 연결 오류가 발생했습니다.');
    } finally {
      app.settingsLoading.style.display = 'none';
    }
  }

  function showSettingsError(message) {
    app.settingsError.textContent = message;
    app.settingsError.style.display = 'block';
  }

  function renderSettings(data) {
    // Config file info
    const configPath = document.getElementById('settings-config-path');
    const configStatus = document.getElementById('settings-config-status');
    configPath.textContent = data.configFile.path || '(없음)';
    configStatus.innerHTML = data.configFile.readOnly 
      ? '<span class="status-badge status-inactive">읽기 전용</span>'
      : '<span class="status-badge status-active">쓰기 가능</span>';
    
    // Server settings
    setText('settings-server-listen', data.server.listen);
    setText('settings-server-public-endpoint', data.server.publicEndpoint || '(미설정)');
    setText('settings-server-enable-ui', data.server.enableUI ? '예' : '아니오');
    setText('settings-server-trust-proxy', data.server.trustProxyHeaders ? '예' : '아니오');
    
    // S3 settings
    setText('settings-s3-region', data.s3.region);
    setText('settings-s3-virtual-host', data.s3.virtualHostSuffix || '(미설정)');
    setText('settings-s3-presign-ttl', data.s3.maxPresignTTL);
    
    // UI settings
    setText('settings-ui-session-ttl', data.ui.sessionTTL);
    setText('settings-ui-idle-ttl', data.ui.sessionIdleTTL);
    
    // Logging settings
    setText('settings-logging-level', data.logging.level);
    setText('settings-logging-access', data.logging.accessLog ? '예' : '아니오');
    
    // GC settings
    setText('settings-gc-orphan-interval', data.gc.orphanScanInterval);
    setText('settings-gc-orphan-grace', data.gc.orphanGracePeriod);
    setText('settings-gc-multipart-expiry', data.gc.multipartExpiry);
    
    // Set env-lock badges
    setEnvLock('settings-lock-server-listen', data.envLocked.serverListen);
    setEnvLock('settings-lock-server-public-endpoint', data.envLocked.serverPublicEndpoint);
    setEnvLock('settings-lock-server-enable-ui', data.envLocked.serverEnableUI);
    setEnvLock('settings-lock-server-trust-proxy', data.envLocked.serverTrustProxyHeaders);
    setEnvLock('settings-lock-s3-region', data.envLocked.s3Region);
    setEnvLock('settings-lock-s3-virtual-host', data.envLocked.s3VirtualHostSuffix);
    setEnvLock('settings-lock-s3-presign-ttl', data.envLocked.s3MaxPresignTTL);
    setEnvLock('settings-lock-ui-session-ttl', data.envLocked.uiSessionTTL);
    setEnvLock('settings-lock-ui-idle-ttl', data.envLocked.uiSessionIdleTTL);
    setEnvLock('settings-lock-logging-level', data.envLocked.loggingLevel);
    setEnvLock('settings-lock-logging-access', data.envLocked.loggingAccessLog);
    setEnvLock('settings-lock-gc-orphan-interval', data.envLocked.gcOrphanScanInterval);
    setEnvLock('settings-lock-gc-orphan-grace', data.envLocked.gcOrphanGracePeriod);
    setEnvLock('settings-lock-gc-multipart-expiry', data.envLocked.gcMultipartExpiry);
    
    // Path status table
    renderPathStatus(data.pathStatus);
  }

  function setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value || '-';
  }

  function setEnvLock(id, locked) {
    const el = document.getElementById(id);
    if (el) el.style.display = locked ? 'inline' : 'none';
  }

  function renderPathStatus(pathStatus) {
    const paths = [
      { label: 'Meta DB', data: pathStatus.metaDB },
      { label: 'Object Root', data: pathStatus.objectRoot },
      { label: 'Multipart Root', data: pathStatus.multipartRoot },
      { label: 'Temp Root', data: pathStatus.tempRoot },
      { label: 'Log Root', data: pathStatus.logRoot }
    ];
    
    app.settingsPathsTbody.innerHTML = paths.map(p => {
      const statusBadge = getPathStatusBadge(p.data);
      const diskUsage = formatDiskUsage(p.data.diskStats);
      return `
        <tr>
          <td class="mono">${escapeHtml(p.data.path || '(미설정)')}</td>
          <td>${escapeHtml(p.data.kind || '-')}</td>
          <td>${statusBadge}</td>
          <td>${diskUsage}</td>
        </tr>
      `;
    }).join('');
  }

  function getPathStatusBadge(pathData) {
    if (!pathData.exists) {
      return '<span class="status-badge status-inactive">없음</span>';
    }
    if (!pathData.writable) {
      return '<span class="status-badge status-warning">읽기 전용</span>';
    }
    return '<span class="status-badge status-active">정상</span>';
  }

  function formatDiskUsage(diskStats) {
    if (!diskStats || diskStats.totalBytes === 0) {
      return '-';
    }
    const total = formatBytes(diskStats.totalBytes);
    const used = formatBytes(diskStats.usedBytes);
    const free = formatBytes(diskStats.freeBytes);
    const usedPercent = Math.round((diskStats.usedBytes / diskStats.totalBytes) * 100);
    return `${used} / ${total} (${usedPercent}% 사용, ${free} 여유)`;
  }

  // ========== Password Change ==========

  function showPasswordChangeMessage(type, message) {
    app.passwordChangeError.style.display = 'none';
    app.passwordChangeSuccess.style.display = 'none';
    
    if (type === 'error') {
      app.passwordChangeError.textContent = message;
      app.passwordChangeError.style.display = 'block';
    } else if (type === 'success') {
      app.passwordChangeSuccess.textContent = message;
      app.passwordChangeSuccess.style.display = 'block';
    }
  }

  function hidePasswordChangeMessages() {
    app.passwordChangeError.style.display = 'none';
    app.passwordChangeSuccess.style.display = 'none';
  }

  function clearPasswordChangeForm() {
    app.currentPasswordInput.value = '';
    app.newPasswordInput.value = '';
  }

  async function changePassword(currentPassword, newPassword) {
    hidePasswordChangeMessages();
    app.passwordChangeBtn.disabled = true;
    app.passwordChangeBtn.textContent = '변경 중...';
    
    try {
      const res = await apiCall('POST', '/ui/api/account/password', {
        currentPassword: currentPassword,
        newPassword: newPassword
      });
      
      // Clear password values from memory immediately
      currentPassword = '';
      newPassword = '';
      clearPasswordChangeForm();
      
      if (res.ok) {
        // Per security-model.md: session is invalidated after password change.
        // Show success message briefly, then redirect to login.
        showPasswordChangeMessage('success', '비밀번호가 변경되었습니다. 다시 로그인해 주세요.');
        
        // Wait 2 seconds for user to see the message, then redirect to login.
        setTimeout(() => {
          currentUser = null;
          csrfToken = null;
          showScreen('login');
          showLoginError('');
        }, 2000);
      } else if (res.status === 401) {
        // Session expired or invalid
        showScreen('login');
      } else if (res.status === 403) {
        const data = await res.json();
        let errorMsg = data.error || '비밀번호 변경에 실패했습니다.';
        // Translate common error messages
        if (data.error && data.error.includes('current password')) {
          errorMsg = '현재 비밀번호가 올바르지 않습니다.';
        } else if (data.error && data.error.includes('CSRF')) {
          errorMsg = 'CSRF 토큰이 유효하지 않습니다. 페이지를 새로고침하고 다시 시도해 주세요.';
        }
        showPasswordChangeMessage('error', errorMsg);
      } else if (res.status === 400) {
        const data = await res.json();
        let errorMsg = data.error || '입력 값이 유효하지 않습니다.';
        if (data.error && data.error.includes('currentPassword')) {
          errorMsg = '현재 비밀번호를 입력해 주세요.';
        } else if (data.error && data.error.includes('newPassword')) {
          errorMsg = '새 비밀번호를 입력해 주세요.';
        }
        showPasswordChangeMessage('error', errorMsg);
      } else {
        const data = await res.json().catch(() => ({}));
        showPasswordChangeMessage('error', data.error || '서버 오류가 발생했습니다.');
      }
    } catch (e) {
      console.error('Failed to change password:', e);
      showPasswordChangeMessage('error', '서버 연결 오류가 발생했습니다.');
    } finally {
      app.passwordChangeBtn.disabled = false;
      app.passwordChangeBtn.textContent = '비밀번호 변경';
    }
  }

  // ========== Access Keys ==========

  function showAccessKeysMessage(type, message) {
    app.accessKeysError.style.display = 'none';
    app.accessKeysSuccess.style.display = 'none';
    
    if (type === 'error') {
      app.accessKeysError.textContent = message;
      app.accessKeysError.style.display = 'block';
    } else if (type === 'success') {
      app.accessKeysSuccess.textContent = message;
      app.accessKeysSuccess.style.display = 'block';
      // Auto-hide success messages after 3 seconds
      setTimeout(() => {
        app.accessKeysSuccess.style.display = 'none';
      }, 3000);
    }
  }

  function hideAccessKeysMessages() {
    app.accessKeysError.style.display = 'none';
    app.accessKeysSuccess.style.display = 'none';
  }

  function hideSecretDisplay() {
    app.accessKeySecretDisplay.style.display = 'none';
    app.newAccessKeyId.textContent = '';
    app.newSecretKey.textContent = '';
    app.newSecretKey.classList.add('secret-blur');
    app.newSecretKey.classList.remove('revealed');
    app.secretToggleBtn.textContent = '보기';
  }

  async function loadAccessKeys() {
    app.accessKeysLoading.style.display = 'block';
    app.accessKeysEmpty.style.display = 'none';
    app.accessKeysTable.style.display = 'none';
    hideAccessKeysMessages();
    
    try {
      const res = await apiCall('GET', '/ui/api/access-keys');
      if (res.ok) {
        const keys = await res.json();
        
        if (keys.length === 0) {
          app.accessKeysEmpty.style.display = 'block';
        } else {
          app.accessKeysTbody.innerHTML = keys.map(key => {
            const statusBadge = key.status === 'active'
              ? '<span class="status-badge status-active">활성</span>'
              : '<span class="status-badge status-inactive">비활성</span>';
            
            const typeBadge = key.isRoot
              ? '<span class="type-badge type-root">Root</span>'
              : '<span class="type-badge type-service">Service</span>';
            
            const lastUsed = key.lastUsedAt ? formatDate(key.lastUsedAt) : '-';
            
            // Action buttons based on key type and status
            let actions = '';
            if (key.isRoot) {
              // Root keys cannot be revoked or deleted
              actions = '<span class="hint">-</span>';
            } else if (key.status === 'active') {
              // Active service keys can be revoked
              actions = `<button class="btn-warning btn-small" data-action="revoke-key">비활성화</button>`;
            } else {
              // Inactive service keys can be deleted
              actions = `<button class="btn-danger btn-small" data-action="delete-key">삭제</button>`;
            }
            
            return `
              <tr data-access-key="${escapeHtml(key.accessKey)}" data-is-root="${key.isRoot}" data-status="${key.status}">
                <td><code>${escapeHtml(key.accessKey)}</code></td>
                <td>${escapeHtml(key.description || '-')}</td>
                <td>${statusBadge}</td>
                <td>${typeBadge}</td>
                <td>${formatDate(key.createdAt)}</td>
                <td>${lastUsed}</td>
                <td class="actions-col">
                  <div class="access-key-actions">${actions}</div>
                </td>
              </tr>
            `;
          }).join('');
          app.accessKeysTable.style.display = 'table';
        }
      } else if (res.status === 401) {
        showScreen('login');
      } else {
        const data = await res.json();
        showAccessKeysMessage('error', data.error || '접근 키 목록을 불러오는데 실패했습니다.');
      }
    } catch (e) {
      console.error('Failed to load access keys:', e);
      showAccessKeysMessage('error', '접근 키 목록을 불러오는데 실패했습니다.');
    } finally {
      app.accessKeysLoading.style.display = 'none';
    }
  }

  async function createAccessKey(description) {
    hideAccessKeysMessages();
    hideSecretDisplay();
    app.accessKeyCreateBtn.disabled = true;
    app.accessKeyCreateBtn.textContent = '생성 중...';
    
    try {
      const res = await apiCall('POST', '/ui/api/access-keys', { description });
      
      if (res.ok || res.status === 201) {
        const data = await res.json();
        
        // Show the secret display panel
        app.newAccessKeyId.textContent = data.accessKey;
        app.newSecretKey.textContent = data.secretKey;
        app.accessKeySecretDisplay.style.display = 'block';
        
        // Clear the form
        app.accessKeyDescriptionInput.value = '';
        
        // Refresh the list (secret won't be visible here)
        loadAccessKeys();
      } else {
        const data = await res.json();
        let errorMsg = data.error || '접근 키 생성에 실패했습니다.';
        if (data.error === 'access key already exists') {
          errorMsg = '접근 키가 이미 존재합니다. 다시 시도해 주세요.';
        }
        showAccessKeysMessage('error', errorMsg);
      }
    } catch (e) {
      if (e.message !== 'setup required') {
        console.error('Failed to create access key:', e);
        showAccessKeysMessage('error', '서버 연결 오류가 발생했습니다.');
      }
    } finally {
      app.accessKeyCreateBtn.disabled = false;
      app.accessKeyCreateBtn.textContent = '새 키 발급';
    }
  }

  async function revokeAccessKey(accessKey) {
    // Confirmation dialog
    if (!confirm(`접근 키 '${accessKey}'를 비활성화하시겠습니까?\n\n비활성화된 키는 더 이상 API 인증에 사용할 수 없습니다.`)) {
      return;
    }
    
    hideAccessKeysMessages();
    
    try {
      const res = await apiCall('POST', '/ui/api/access-keys/revoke', { accessKey });
      
      if (res.ok) {
        showAccessKeysMessage('success', `접근 키 '${accessKey}'가 비활성화되었습니다.`);
        loadAccessKeys(); // Refresh the list
      } else {
        const data = await res.json();
        let errorMsg = data.error || '접근 키 비활성화에 실패했습니다.';
        if (data.error === 'cannot revoke root access key') {
          errorMsg = 'Root 키는 비활성화할 수 없습니다.';
        } else if (data.error === 'access key not found') {
          errorMsg = '접근 키를 찾을 수 없습니다.';
        }
        showAccessKeysMessage('error', errorMsg);
      }
    } catch (e) {
      if (e.message !== 'setup required') {
        console.error('Failed to revoke access key:', e);
        showAccessKeysMessage('error', '서버 연결 오류가 발생했습니다.');
      }
    }
  }
  window.revokeAccessKey = revokeAccessKey;

  async function deleteAccessKey(accessKey) {
    // Confirmation dialog - two-step confirmation for delete
    if (!confirm(`접근 키 '${accessKey}'를 삭제하시겠습니까?\n\n⚠️ 이 작업은 되돌릴 수 없습니다.`)) {
      return;
    }
    
    hideAccessKeysMessages();
    
    try {
      const res = await apiCall('POST', '/ui/api/access-keys/delete', { accessKey });
      
      if (res.ok) {
        showAccessKeysMessage('success', `접근 키 '${accessKey}'가 삭제되었습니다.`);
        loadAccessKeys(); // Refresh the list
      } else {
        const data = await res.json();
        let errorMsg = data.error || '접근 키 삭제에 실패했습니다.';
        if (data.error === 'cannot delete root access key') {
          errorMsg = 'Root 키는 삭제할 수 없습니다.';
        } else if (data.error === 'cannot delete active access key; revoke first') {
          errorMsg = '활성 상태의 키는 삭제할 수 없습니다. 먼저 비활성화해 주세요.';
        } else if (data.error === 'access key not found') {
          errorMsg = '접근 키를 찾을 수 없습니다.';
        }
        showAccessKeysMessage('error', errorMsg);
      }
    } catch (e) {
      if (e.message !== 'setup required') {
        console.error('Failed to delete access key:', e);
        showAccessKeysMessage('error', '서버 연결 오류가 발생했습니다.');
      }
    }
  }
  window.deleteAccessKey = deleteAccessKey;

  function copyToClipboard(targetId) {
    const element = document.getElementById(targetId);
    if (!element) return;
    
    const text = element.textContent;
    navigator.clipboard.writeText(text).then(() => {
      showAccessKeysMessage('success', '클립보드에 복사되었습니다.');
    }).catch(() => {
      // Fallback for browsers that don't support clipboard API
      const textarea = document.createElement('textarea');
      textarea.value = text;
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand('copy');
      document.body.removeChild(textarea);
      showAccessKeysMessage('success', '클립보드에 복사되었습니다.');
    });
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
  
  // Event delegation for bucket table actions
  app.bucketsTbody.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-action="delete-bucket"]');
    if (btn) {
      const row = btn.closest('tr');
      const bucketName = row?.dataset.bucketName;
      if (bucketName) {
        deleteBucket(bucketName);
      }
    }
  });
  
  // Event delegation for object table actions
  app.objectsTbody.addEventListener('click', (e) => {
    const target = e.target;
    
    // Folder link click
    const folderLink = target.closest('[data-action="navigate-prefix"]');
    if (folderLink) {
      e.preventDefault();
      const row = folderLink.closest('tr');
      const prefix = row?.dataset.prefix;
      if (prefix !== undefined) {
        navigateToPrefix(prefix);
      }
      return;
    }
    
    // Object row actions
    const actionBtn = target.closest('[data-action]');
    if (actionBtn) {
      const action = actionBtn.dataset.action;
      const row = actionBtn.closest('tr');
      if (!row) return;
      
      const bucket = row.dataset.bucket;
      const key = row.dataset.key;
      
      if (action === 'show-meta' && bucket && key) {
        showObjectMeta(bucket, key);
      } else if (action === 'download' && bucket && key) {
        downloadObject(bucket, key);
      } else if (action === 'delete' && bucket && key) {
        deleteObject(bucket, key);
      }
    }
  });
  
  // Event delegation for breadcrumb navigation
  app.objectBreadcrumb.addEventListener('click', (e) => {
    const link = e.target.closest('[data-breadcrumb-prefix]');
    if (link) {
      e.preventDefault();
      const prefix = link.dataset.breadcrumbPrefix;
      navigateToPrefix(prefix);
    }
  });
  
  // Object upload form
  app.objectUploadForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const key = app.objectKeyInput.value.trim();
    const file = app.objectFileInput.files[0];
    
    if (!objectsState.bucket) {
      showObjectsMessage('error', '버킷을 먼저 선택해 주세요.');
      return;
    }
    
    if (!key) {
      showObjectsMessage('error', '오브젝트 키를 입력해 주세요.');
      return;
    }
    
    if (!file) {
      showObjectsMessage('error', '파일을 선택해 주세요.');
      return;
    }
    
    uploadObject(objectsState.bucket, key, file);
  });
  
  // Auto-fill key when file is selected
  app.objectFileInput.addEventListener('change', () => {
    const file = app.objectFileInput.files[0];
    if (file && !app.objectKeyInput.value) {
      // Use current prefix + filename as default key
      app.objectKeyInput.value = (objectsState.prefix || '') + file.name;
    } else if (file && app.objectKeyInput.value === objectsState.prefix) {
      // If key is just the prefix, append filename
      app.objectKeyInput.value = objectsState.prefix + file.name;
    }
  });

  // Access Key event listeners
  app.accessKeyCreateForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const description = app.accessKeyDescriptionInput.value.trim();
    createAccessKey(description);
  });

  // Event delegation for access keys table actions
  app.accessKeysTbody.addEventListener('click', (e) => {
    const row = e.target.closest('tr');
    if (!row) return;
    
    const accessKey = row.dataset.accessKey;
    if (!accessKey) return;
    
    const revokeBtn = e.target.closest('[data-action="revoke-key"]');
    if (revokeBtn) {
      revokeAccessKey(accessKey);
      return;
    }
    
    const deleteBtn = e.target.closest('[data-action="delete-key"]');
    if (deleteBtn) {
      deleteAccessKey(accessKey);
      return;
    }
  });

  // Secret panel buttons
  app.secretToggleBtn.addEventListener('click', () => {
    const isBlurred = app.newSecretKey.classList.contains('secret-blur');
    if (isBlurred) {
      app.newSecretKey.classList.remove('secret-blur');
      app.newSecretKey.classList.add('revealed');
      app.secretToggleBtn.textContent = '숨기기';
    } else {
      app.newSecretKey.classList.add('secret-blur');
      app.newSecretKey.classList.remove('revealed');
      app.secretToggleBtn.textContent = '보기';
    }
  });

  app.secretDismissBtn.addEventListener('click', hideSecretDisplay);

  // Copy buttons in secret panel
  app.accessKeySecretDisplay.addEventListener('click', (e) => {
    const copyBtn = e.target.closest('[data-copy-target]');
    if (copyBtn) {
      const targetId = copyBtn.dataset.copyTarget;
      copyToClipboard(targetId);
    }
  });

  // Password change form
  app.passwordChangeForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const currentPassword = app.currentPasswordInput.value;
    const newPassword = app.newPasswordInput.value;
    
    if (!currentPassword) {
      showPasswordChangeMessage('error', '현재 비밀번호를 입력해 주세요.');
      return;
    }
    if (!newPassword) {
      showPasswordChangeMessage('error', '새 비밀번호를 입력해 주세요.');
      return;
    }
    
    changePassword(currentPassword, newPassword);
  });

  // ========== Initialize ==========

  checkAuth();

})();
