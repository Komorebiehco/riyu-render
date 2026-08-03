const statusLabels = {
  VERIFIED: '已完成',
  SANITIZING: '处理中',
  PENDING: '待处理',
  FAILED: '异常'
};

const state = {
  tasks: [],
  events: [],
  steps: [],
  failures: [],
  chart: { labels: [], success: [], failed: [] },
  chartRange: 'week',
  summary: null,
  logsPaused: false,
  taskLimit: 50,
  taskTimer: null,
  taskSeq: 0,
  chartSeq: 0,
  exports: [],
  exportFilter: 'all',
  exportBusy: false,
  importStatus: { state: 'idle', message: '' },
  importTimer: null,
  selectedFiles: []
};

const $ = selector => document.querySelector(selector);
const $$ = selector => [...document.querySelectorAll(selector)];

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, char => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  }[char]));
}

async function apiFetch(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: { Accept: 'application/json', ...(options.headers || {}) },
    cache: 'no-store'
  });
  if (!response.ok) {
    const message = (await response.text()).trim();
    throw new Error(message || `HTTP ${response.status}`);
  }
  if (response.status === 204) return null;
  return response.json();
}

function parseDate(value) {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

function relativeTime(value) {
  const date = parseDate(value);
  if (!date) return '--';
  const seconds = Math.max(0, Math.floor((Date.now() - date.getTime()) / 1000));
  if (seconds < 10) return '刚刚';
  if (seconds < 60) return `${seconds} 秒前`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} 分钟前`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} 小时前`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days} 天前`;
  return date.toLocaleDateString('zh-CN');
}

function formatElapsed(seconds) {
  if (seconds === null || seconds === undefined || Number.isNaN(Number(seconds))) {
    return '--';
  }
  const value = Number(seconds);
  if (value < 60) return `${value.toFixed(1)}s`;
  const minutes = Math.floor(value / 60);
  const rest = Math.round(value % 60);
  return `${minutes}分${rest}秒`;
}

function setServiceState(online, checkedAt = new Date()) {
  $('#servicePulse').classList.toggle('offline', !online);
  $('#serviceStatus').textContent = online ? '服务已连接' : '服务未连接';
  $('#serviceMode').textContent =
    (state.summary && state.summary.service && state.summary.service.mode) ||
    (online ? '管理模式' : '--');
  $('#serviceChecked').textContent =
    `最近检查：${checkedAt.toLocaleTimeString('zh-CN', { hour12: false })}`;
  const chip = document.querySelector('.system-chip');
  if (chip) {
    chip.innerHTML = `<span class="pulse${online ? '' : ' offline'}"></span>${online ? '系统在线' : '系统离线'}`;
  }
  const rate = online && state.summary ? Number(state.summary.success_rate) || 0 : 0;
  $('#serviceMeter').style.width = `${Math.max(0, Math.min(100, rate))}%`;
}

function renderSteps() {
  const list = $('#stepList');
  if (!state.steps.length) {
    list.innerHTML = '<div class="empty-row" style="grid-column:1 / -1;height:60px;">暂无步骤数据</div>';
    return;
  }
  list.innerHTML = state.steps.map((step, index) => {
    const rate = Number(step.rate) || 0;
    const active = Number(step.active) || 0;
    const activeLabel = active ? `<em>处理中 ${active}</em>` : '';
    return `
      <div class="step-item${active ? ' active' : ''}">
        <div class="step-meta"><span>${index + 1}. ${escapeHtml(step.name)} ${activeLabel}</span><b>${rate.toFixed(1)}%</b></div>
        <div class="step-track"><i style="width:${Math.min(100, Math.max(0, rate))}%"></i></div>
      </div>`;
  }).join('');
  $('#healthScore').textContent = state.steps.health ?? 0;
}

function renderFailures() {
  const box = $('#failureBars');
  $('#totalFailures').textContent = `共 ${state.failures.total ?? 0} 条`;
  if (!state.failures.items || !state.failures.items.length) {
    box.innerHTML = '<div class="empty-row" style="height:60px;">暂无异常数据</div>';
    return;
  }
  const max = Math.max(...state.failures.items.map(item => item.count), 1);
  box.innerHTML = state.failures.items.map(item => {
    const width = max ? Math.round(item.count / max * 100) : 0;
    return `
      <div class="failure-item">
        <div><span>${escapeHtml(item.label)}</span><b>${item.count}</b></div>
        <progress max="100" value="${width}"></progress>
      </div>`;
  }).join('');
}

function renderTasks() {
  const body = $('#taskTableBody');
  if (!state.tasks.length) {
    body.innerHTML = '<tr><td class="empty-row" colspan="7">没有匹配的任务</td></tr>';
  } else {
    body.innerHTML = state.tasks.map(task => {
      const label = statusLabels[task.status] || task.status;
      const failure = task.failure ? ` · ${escapeHtml(task.failure)}` : '';
      const progress = Math.min(100, Math.max(0, Number(task.progress) || 0));
      const processing = task.status === 'SANITIZING';
      const currentStep = Number(task.current_step) || 0;
      const currentName = task.current_step_name || '';
      const stepLabel = processing && currentStep
        ? `<small>第 ${currentStep}/8 步 · ${escapeHtml(currentName)}</small>`
        : '';
      const deleteTitle = processing ? '正在处理的任务暂时不能删除' : `删除任务 ${escapeHtml(task.id)}`;
      return `
        <tr>
          <td><span class="task-id">${escapeHtml(task.id)}</span></td>
          <td><div class="account-cell"><span class="account-badge">G</span>${escapeHtml(task.account)}</div></td>
          <td><span class="status-badge status-${escapeHtml(task.status)}" title="${failure || '运行正常'}">${label}</span></td>
          <td class="progress-cell"><div class="progress-info"><div><div class="mini-progress"><i style="width:${progress}%"></i></div>${stepLabel}</div><span>${progress}%</span></div></td>
          <td>${formatElapsed(task.elapsed_seconds)}</td>
          <td>${relativeTime(task.updated_at)}</td>
          <td><button class="row-action row-delete" data-delete-task="${escapeHtml(task.key)}" data-task-id="${escapeHtml(task.id)}" title="${deleteTitle}" ${processing ? 'disabled' : ''}>删除</button></td>
        </tr>`;
    }).join('');
  }
  $('#tableCount').textContent = `显示 ${state.tasks.length} 条记录`;
  $('#navTaskCount').textContent = state.summary ? state.summary.total : state.tasks.length;
}

function renderActivities() {
  const items = state.events.slice(0, 4);
  const stream = $('#activityStream');
  if (!items.length) {
    stream.innerHTML = '<div class="empty-row" style="grid-column:1 / -1;height:60px;">暂无活动事件</div>';
    return;
  }
  stream.innerHTML = items.map(item => {
    const type = ['success', 'info', 'warning', 'error'].includes(item.type) ? item.type : 'info';
    return `
      <div class="activity-item ${type}"><i></i><div><p>${escapeHtml(item.text)}</p><small>${relativeTime(item.time)}</small></div></div>`;
  }).join('');
}

function formatFileSize(bytes) {
  const value = Number(bytes) || 0;
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / 1024 / 1024).toFixed(1)} MB`;
}

function formatDateTime(value) {
  const date = parseDate(value);
  if (!date) return '--';
  return date.toLocaleString('zh-CN', { hour12: false });
}

function isEmptyExport(file) {
  return Boolean(file.empty) || (Number(file.lines) || 0) === 0 || (Number(file.size) || 0) === 0;
}

function renderExports() {
  const body = $('#exportTableBody');
  const files = state.exports || [];
  const emptyFiles = files.filter(isEmptyExport);
  const validFiles = files.filter(file => !isEmptyExport(file));
  const totalSize = files.reduce((sum, file) => sum + (Number(file.size) || 0), 0);
  const visibleFiles = files.filter(file => {
    if (state.exportFilter === 'valid') return !isEmptyExport(file);
    if (state.exportFilter === 'empty') return isEmptyExport(file);
    return true;
  });

  $('#exportCount').textContent = files.length;
  $('#exportCountLabel').textContent = emptyFiles.length
    ? `共 ${files.length} 个 · ${emptyFiles.length} 个待清理`
    : `共 ${files.length} 个文件`;
  $('#validExportCount').textContent = validFiles.length;
  $('#invalidExportCount').textContent = emptyFiles.length;
  $('#exportTotalSize').textContent = formatFileSize(totalSize);
  $('#emptyExportCount').textContent = emptyFiles.length;
  const cleanupButton = $('#cleanupEmptyExports');
  cleanupButton.disabled = state.exportBusy || emptyFiles.length === 0;

  if (!files.length) {
    body.innerHTML = '<tr><td class="empty-row export-empty-state" colspan="6"><strong>结果目录很干净</strong><span>完成清洗后，有效结果会显示在这里</span></td></tr>';
    return;
  }
  if (!visibleFiles.length) {
    body.innerHTML = '<tr><td class="empty-row export-empty-state" colspan="6"><strong>当前筛选没有文件</strong><span>可以切换上方筛选条件</span></td></tr>';
    return;
  }

  body.innerHTML = visibleFiles.map(file => {
    const empty = isEmptyExport(file);
    const encodedName = encodeURIComponent(file.name);
    return `
    <tr class="${empty ? 'export-row-empty' : ''}">
      <td><div class="export-file-cell">
        <span class="export-file-icon">TXT</span>
        <div><strong>${escapeHtml(file.name)}</strong><small>${empty ? '无有效账号，可安全清理' : '清洗结果文件'}</small></div>
      </div></td>
      <td><span class="export-status ${empty ? 'empty' : 'valid'}"><i></i>${empty ? '空文件' : '可用'}</span></td>
      <td>${Number(file.lines) || 0}</td>
      <td>${formatFileSize(file.size)}</td>
      <td>${formatDateTime(file.created_at)}</td>
      <td><div class="export-actions">
        ${empty ? '' : `<button data-view-file="${encodedName}">查看</button><button data-download-file="${encodedName}">下载</button>`}
        <button class="export-delete" data-delete-file="${encodedName}">删除</button>
      </div></td>
    </tr>`;
  }).join('');
}

function normalizeImportState(value) {
  const status = String(value || 'idle').toLowerCase();
  if (['pending', 'waiting'].includes(status)) return 'queued';
  if (['completed', 'success'].includes(status)) return 'done';
  if (['failed'].includes(status)) return 'error';
  return status;
}

function importJobsFromStatus(status) {
  if (Array.isArray(status?.jobs)) return status.jobs;
  if (status?.state && status.state !== 'idle') return [status];
  return [];
}

function renderImportStatus() {
  const status = state.importStatus || { state: 'idle' };
  const jobs = importJobsFromStatus(status);
  const runningJobs = jobs.filter(job => normalizeImportState(job.state || job.status) === 'running');
  const queuedJobs = jobs.filter(job => normalizeImportState(job.state || job.status) === 'queued');
  const latestJob = jobs.at(-1);
  const running = runningJobs[0];
  const el = $('#importStatus');

  el.classList.remove('running', 'done', 'error');
  if (running) {
    el.classList.add('running');
    const source = running.source || running.source_name || '当前批次';
    el.textContent = `正在执行「${source}」：${Number(running.completed) || 0}/${Number(running.total) || 0}，后面还有 ${queuedJobs.length} 个等待批次`;
  } else if (queuedJobs.length) {
    el.classList.add('running');
    el.textContent = `已有 ${queuedJobs.length} 个批次等待执行，系统将按加入顺序处理`;
  } else if (latestJob && normalizeImportState(latestJob.state || latestJob.status) === 'error') {
    el.classList.add('error');
    el.textContent = `最近批次异常：${latestJob.message || '未知错误'}`;
  } else if (latestJob) {
    el.classList.add('done');
    el.textContent = latestJob.message || `最近批次已完成：成功 ${Number(latestJob.verified) || 0} 个，失败 ${Number(latestJob.failed) || 0} 个`;
  } else {
    el.textContent = status.message || '当前没有执行中的批次';
  }

  renderImportQueue(jobs);
}

function renderImportQueue(jobs) {
  const list = $('#importQueueList');
  const summary = $('#importQueueSummary');
  if (!list || !summary) return;

  const active = jobs.filter(job => ['running', 'queued'].includes(normalizeImportState(job.state || job.status)));
  const runningCount = active.filter(job => normalizeImportState(job.state || job.status) === 'running').length;
  const queuedCount = active.length - runningCount;
  summary.textContent = active.length
    ? `${runningCount ? `${runningCount} 执行中` : ''}${runningCount && queuedCount ? ' · ' : ''}${queuedCount ? `${queuedCount} 等待` : ''}`
    : (jobs.length ? `最近 ${jobs.length} 个批次` : '队列为空');

  if (!jobs.length) {
    list.innerHTML = '<div class="import-queue-empty">还没有批次，选择文件或直接输入账号后加入队列</div>';
    return;
  }

  list.innerHTML = jobs.slice(-12).map((job, index) => {
    const jobState = normalizeImportState(job.state || job.status);
    const total = Number(job.total) || 0;
    const completed = Number(job.completed) || 0;
    const progress = jobState === 'done' ? 100 : (total ? Math.min(100, Math.round(completed / total * 100)) : 0);
    const source = job.source || job.source_name || (job.source_type === 'text' ? '直接输入' : 'TXT 文件');
    const statusLabels = { queued: '等待中', running: '执行中', done: '已完成', error: '异常' };
    const safeState = ['queued', 'running', 'done', 'error'].includes(jobState) ? jobState : 'queued';
    return `
      <div class="import-job status-${safeState}" title="${escapeHtml(job.message || '')}">
        <span class="import-job-index">${String(index + 1).padStart(2, '0')}</span>
        <div class="import-job-main">
          <strong>${escapeHtml(source)}</strong>
          <small>${total} 个账号 · 成功 ${Number(job.verified) || 0} · 失败 ${Number(job.failed) || 0}</small>
        </div>
        <div class="import-job-progress">
          <span class="import-job-track"><i style="width:${progress}%"></i></span>
          <span>${progress}%</span>
        </div>
        <span class="import-job-status ${safeState}">${statusLabels[safeState]}</span>
      </div>`;
  }).join('');
}

async function loadExports() {
  const data = await apiFetch('/api/exports');
  state.exports = data.files || [];
  renderExports();
}

async function deleteExportFile(fileName, button) {
  if (!window.confirm(`确定删除“${fileName}”吗？\n删除后无法从控制台恢复。`)) return;
  const originalText = button.textContent;
  button.disabled = true;
  button.textContent = '删除中';
  try {
    const data = await apiFetch(`/api/exports/${encodeURIComponent(fileName)}`, { method: 'DELETE' });
    showToast(data?.message || '文件已删除');
    await loadExports();
  } catch (error) {
    showToast(`删除失败：${error.message}`);
    button.disabled = false;
    button.textContent = originalText;
  }
}

async function cleanupEmptyExportFiles() {
  const count = (state.exports || []).filter(isEmptyExport).length;
  if (!count || state.exportBusy) return;
  if (!window.confirm(`将删除 ${count} 个无有效账号的空文件。\n有效结果不会受到影响，是否继续？`)) return;

  const button = $('#cleanupEmptyExports');
  const label = $('#cleanupEmptyLabel');
  state.exportBusy = true;
  button.disabled = true;
  label.textContent = '正在清理…';
  try {
    const data = await apiFetch('/api/exports/cleanup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: 'empty' })
    });
    showToast(data?.message || `已清理 ${data?.deleted || count} 个空文件`);
    await loadExports();
  } catch (error) {
    showToast(`清理失败：${error.message}`);
  } finally {
    state.exportBusy = false;
    label.textContent = '清理空文件';
    renderExports();
  }
}

async function loadImportStatus() {
  state.importStatus = await apiFetch('/api/import/status');
  renderImportStatus();
}

function fileIdentity(file) {
  return `${file.name}:${file.size}:${file.lastModified}`;
}

function renderSelectedFiles() {
  const queue = $('#selectedFileQueue');
  const files = state.selectedFiles || [];
  $('#selectedFileCount').textContent = files.length;
  $('#uploadButton').disabled = files.length === 0;
  if (!files.length) {
    queue.innerHTML = '<span class="selected-files-empty">尚未选择文件</span>';
    return;
  }
  queue.innerHTML = files.map((file, index) => `
    <span class="selected-file-chip">
      <i>${String(index + 1).padStart(2, '0')}</i>
      <span title="${escapeHtml(file.name)}">${escapeHtml(file.name)}</span>
      <button type="button" data-remove-selected-file="${index}" aria-label="移除 ${escapeHtml(file.name)}">×</button>
    </span>`).join('');
}

function handleFileSelect(input) {
  const incoming = input instanceof File ? [input] : [...(input || [])];
  if (!incoming.length) return;
  const txtFiles = incoming.filter(file => file.name.toLowerCase().endsWith('.txt'));
  if (txtFiles.length !== incoming.length) showToast('已忽略非 .txt 文件');

  const existing = new Set((state.selectedFiles || []).map(fileIdentity));
  txtFiles.forEach(file => {
    const key = fileIdentity(file);
    if (!existing.has(key)) {
      state.selectedFiles.push(file);
      existing.add(key);
    }
  });
  renderSelectedFiles();
}

async function readResponseData(response) {
  const text = await response.text();
  if (!text) return {};
  try { return JSON.parse(text); } catch { return { message: text }; }
}

async function uploadSelectedFiles() {
  const files = [...(state.selectedFiles || [])];
  if (!files.length) return;
  const button = $('#uploadButton');
  const label = $('#uploadQueueLabel');
  const succeeded = new Set();
  const failures = [];
  button.disabled = true;
  label.textContent = '正在提交…';

  for (const file of files) {
    const form = new FormData();
    form.append('file', file);
    try {
      const response = await fetch('/api/import/txt', { method: 'POST', body: form });
      const data = await readResponseData(response);
      if (!response.ok) throw new Error(data.message || `HTTP ${response.status}`);
      succeeded.add(fileIdentity(file));
    } catch (error) {
      failures.push(`${file.name}：${error.message}`);
    }
  }

  state.selectedFiles = state.selectedFiles.filter(file => !succeeded.has(fileIdentity(file)));
  label.textContent = '加入队列';
  renderSelectedFiles();
  if (succeeded.size) showToast(`已按顺序加入 ${succeeded.size} 个 TXT 批次`);
  if (failures.length) showToast(`有 ${failures.length} 个文件提交失败`);
  await Promise.allSettled([loadImportStatus(), loadTasks(), loadSummary(), loadExports()]);
}

function updateCredentialLineCount() {
  const input = $('#credentialTextInput');
  const lines = input.value.split(/\r?\n/).filter(line => line.trim()).length;
  $('#credentialLineCount').textContent = `${lines} 行待提交`;
  $('#queueTextButton').disabled = lines === 0;
  return lines;
}

async function queueTextCredentials() {
  const input = $('#credentialTextInput');
  const content = input.value.trim();
  const lines = updateCredentialLineCount();
  if (!content || !lines) return;

  const button = $('#queueTextButton');
  button.disabled = true;
  button.textContent = '正在提交…';
  try {
    const response = await fetch('/api/import/text', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ content })
    });
    const data = await readResponseData(response);
    if (!response.ok) throw new Error(data.message || `HTTP ${response.status}`);
    input.value = '';
    updateCredentialLineCount();
    showToast(data.message || `已将 ${lines} 行账号追加到执行队列`);
    await Promise.allSettled([loadImportStatus(), loadTasks(), loadSummary(), loadExports()]);
  } catch (error) {
    showToast(`提交失败：${error.message}`);
  } finally {
    button.textContent = '加入队列';
    updateCredentialLineCount();
  }
}

async function openExportView(fileName) {
  const url = `/api/exports/content?file=${encodeURIComponent(fileName)}`;
  const response = await fetch(url, { cache: 'no-store' });
  if (!response.ok) {
    showToast(`文件读取失败：HTTP ${response.status}`);
    return;
  }
  const text = await response.text();
  $('#exportModalTitle').textContent = fileName;
  $('#exportModalContent').textContent = text;
  const download = $('#exportDownload');
  download.href = url;
  download.download = fileName;
  const modal = $('#exportModal');
  modal.classList.add('open');
  modal.setAttribute('aria-hidden', 'false');
}

function closeExportView() {
  const modal = $('#exportModal');
  modal.classList.remove('open');
  modal.setAttribute('aria-hidden', 'true');
}

function drawChart(range = state.chartRange) {
  state.chartRange = range;
  const canvas = $('#trendChart');
  const labels = state.chart.labels || [];
  const success = state.chart.success || [];
  const failed = state.chart.failed || [];
  const box = canvas.getBoundingClientRect();
  const ratio = window.devicePixelRatio || 1;
  canvas.width = Math.max(300, box.width * ratio);
  canvas.height = Math.max(180, box.height * ratio);
  const ctx = canvas.getContext('2d');
  ctx.scale(ratio, ratio);
  const w = canvas.width / ratio;
  const h = canvas.height / ratio;
  const pad = { left: 34, right: 12, top: 14, bottom: 27 };
  const innerW = w - pad.left - pad.right;
  const innerH = h - pad.top - pad.bottom;
  const max = Math.ceil(Math.max(0, ...success, ...failed) / 50) * 50 || 100;
  const styles = getComputedStyle(document.body);
  const border = styles.getPropertyValue('--border').trim();
  const muted = styles.getPropertyValue('--muted').trim();
  const surface = styles.getPropertyValue('--surface').trim();
  const primary = styles.getPropertyValue('--primary').trim();

  ctx.clearRect(0, 0, w, h);
  ctx.font = '9px Inter, sans-serif';
  ctx.fillStyle = muted;
  ctx.strokeStyle = border;
  ctx.lineWidth = 1;
  ctx.textAlign = 'right';
  for (let i = 0; i <= 4; i++) {
    const y = pad.top + innerH * i / 4;
    ctx.beginPath();
    ctx.moveTo(pad.left, y);
    ctx.lineTo(w - pad.right, y);
    ctx.stroke();
    ctx.fillText(String(Math.round(max * (4 - i) / 4)), pad.left - 8, y + 3);
  }
  ctx.textAlign = 'center';
  labels.forEach((label, i) => {
    const x = pad.left + innerW * i / Math.max(1, labels.length - 1);
    ctx.fillText(label, x, h - 8);
  });

  function line(values, color, fill) {
    const points = values.map((value, i) => ({
      x: pad.left + innerW * i / Math.max(1, values.length - 1),
      y: pad.top + innerH - (Number(value) / max * innerH)
    }));
    if (!points.length) return;
    if (fill) {
      const gradient = ctx.createLinearGradient(0, pad.top, 0, h - pad.bottom);
      gradient.addColorStop(0, 'rgba(82,125,78,.28)');
      gradient.addColorStop(1, 'rgba(82,125,78,0)');
      ctx.beginPath();
      ctx.moveTo(points[0].x, h - pad.bottom);
      points.forEach(point => ctx.lineTo(point.x, point.y));
      ctx.lineTo(points.at(-1).x, h - pad.bottom);
      ctx.closePath();
      ctx.fillStyle = gradient;
      ctx.fill();
    }
    ctx.beginPath();
    points.forEach((point, i) => (i ? ctx.lineTo(point.x, point.y) : ctx.moveTo(point.x, point.y)));
    ctx.strokeStyle = color;
    ctx.lineWidth = 2;
    ctx.lineJoin = 'round';
    ctx.stroke();
    points.forEach(point => {
      ctx.beginPath();
      ctx.arc(point.x, point.y, 3, 0, Math.PI * 2);
      ctx.fillStyle = surface;
      ctx.fill();
      ctx.strokeStyle = color;
      ctx.lineWidth = 1.5;
      ctx.stroke();
    });
  }
  line(success, primary, true);
  line(failed, '#fb7185', false);
}

function animateCounters() {
  $$('[data-counter]').forEach(element => {
    const target = Number(element.dataset.counter);
    const decimal = Number(element.dataset.decimal || 0);
    const start = performance.now();
    const duration = 650;
    function tick(now) {
      const progress = Math.min((now - start) / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      element.textContent = (target * eased).toLocaleString('zh-CN', {
        minimumFractionDigits: decimal,
        maximumFractionDigits: decimal
      });
      if (progress < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  });
}

function setMetric(id, value, decimal = 0) {
  const element = $(id);
  element.dataset.counter = Number(value) || 0;
  element.dataset.decimal = decimal;
}

function applySummary(summary) {
  state.summary = summary;
  const total = Number(summary.total) || 0;
  const distribution = summary.distribution || {};
  setMetric('#metricTotal', total);
  setMetric('#metricSuccess', Number(summary.success_rate) || 0, 1);
  setMetric('#metricProcessing', Number(summary.processing) || 0);
  setMetric('#metricElapsed', Number(summary.avg_elapsed_seconds) || 0, 1);
  animateCounters();
  $('#metricSuccessHint').textContent = `已完成 ${Number(summary.completed) || 0} 个任务`;
  $('#metricProcessingHint').textContent = `待处理 ${Number(summary.pending) || 0} 个任务`;
  $('#donutTotal').textContent = total;
  $('#navTaskCount').textContent = total;
  const pct = value => (total ? Math.round((Number(value) || 0) / total * 100) : 0);
  const verifiedPct = pct(distribution.VERIFIED);
  const processingPct = pct(distribution.SANITIZING);
  const pendingPct = pct(distribution.PENDING);
  const failedPct = pct(distribution.FAILED);
  $('#distributionVerified').textContent = `${verifiedPct}%`;
  $('#distributionProcessing').textContent = `${processingPct}%`;
  $('#distributionPending').textContent = `${pendingPct}%`;
  $('#distributionFailed').textContent = `${failedPct}%`;

  const colors = ['#2c6bed', '#20b486', '#f4a62a', '#eb5a69'];
  const parts = [verifiedPct, processingPct, pendingPct, failedPct];
  const segments = [];
  let start = 0;
  parts.forEach((part, index) => {
    if (!part) return;
    segments.push(`${colors[index]} ${start}% ${start + part}%`);
    start += part;
  });
  const donut = $('#donutChart');
  donut.style.background = segments.length
    ? `conic-gradient(${segments.join(', ')})`
    : '#e7ebf2';
}

async function loadSummary() {
  const summary = await apiFetch('/api/dashboard/summary');
  applySummary(summary);
  const checked = parseDate(summary.updated_at) || new Date();
  $('#currentTime').textContent = `数据更新于 ${checked.toLocaleTimeString('zh-CN', { hour12: false })}`;
  setServiceState(true, checked);
}

async function loadTrend(range = state.chartRange) {
  state.chartRange = range;
  const seq = ++state.chartSeq;
  const data = await apiFetch(`/api/dashboard/trend?range=${encodeURIComponent(range)}`);
  if (seq !== state.chartSeq) return;
  state.chart = {
    labels: data.labels || [],
    success: data.success || [],
    failed: data.failed || []
  };
  drawChart(range);
}

async function loadSteps() {
  const data = await apiFetch('/api/dashboard/steps');
  state.steps = data.steps || [];
  renderSteps();
}

async function loadFailures() {
  state.failures = await apiFetch('/api/dashboard/failures');
  renderFailures();
}

async function loadTasks() {
  const seq = ++state.taskSeq;
  const params = new URLSearchParams({ limit: String(state.taskLimit) });
  const status = $('#statusFilter').value;
  const query = $('#taskSearch').value.trim();
  if (status !== 'all') params.set('status', status);
  if (query) params.set('query', query);
  const data = await apiFetch(`/api/tasks?${params.toString()}`);
  if (seq !== state.taskSeq) return;
  state.tasks = data.items || [];
  renderTasks();
}

async function deleteTask(button) {
  const taskKey = button.dataset.deleteTask;
  const taskId = button.dataset.taskId || '此任务';
  if (!taskKey || !window.confirm(`确定删除任务 ${taskId}？此操作无法撤销。`)) return;

  const originalText = button.textContent;
  button.disabled = true;
  button.textContent = '删除中';
  try {
    await apiFetch(`/api/tasks/${encodeURIComponent(taskKey)}`, { method: 'DELETE' });
    await refreshAll({ silent: true });
    showToast(`任务 ${taskId} 已删除`);
  } catch (error) {
    button.disabled = false;
    button.textContent = originalText;
    showToast(error.message || '删除任务失败');
  }
}

async function loadEvents() {
  if (state.logsPaused) return;
  const data = await apiFetch('/api/events');
  state.events = data.items || [];
  renderActivities();
}

async function refreshAll({ silent = false } = {}) {
  const results = await Promise.allSettled([
    loadSummary(),
    loadSteps(),
    loadFailures(),
    loadTasks(),
    loadEvents(),
    loadTrend(state.chartRange),
    loadExports(),
    loadImportStatus()
  ]);
  const online = results.every(result => result.status === 'fulfilled');
  setServiceState(online, new Date());
  if (online && !silent) showToast('数据已刷新');
  if (!online && !silent) showToast('后端服务未连接，请先启动 dashboard');
}

function showToast(message) {
  const toast = $('#toast');
  toast.querySelector('p').textContent = message;
  toast.classList.add('show');
  clearTimeout(showToast.timer);
  showToast.timer = setTimeout(() => toast.classList.remove('show'), 2200);
}

function setTime() {
  const now = new Date();
  $('#currentTime').textContent = `数据更新于 ${now.toLocaleTimeString('zh-CN', { hour12: false })}`;
}

function initEvents() {
  $('#taskSearch').addEventListener('input', () => {
    clearTimeout(state.taskTimer);
    state.taskTimer = setTimeout(loadTasks, 250);
  });
  $('#statusFilter').addEventListener('change', loadTasks);
  $('#taskTableBody').addEventListener('click', event => {
    const button = event.target.closest('[data-delete-task]');
    if (button && !button.disabled) deleteTask(button);
  });
  $('#refreshButton').addEventListener('click', () => refreshAll());
  $('#themeButton').addEventListener('click', () => {
    document.body.classList.toggle('dark');
    $('#themeButton').textContent = document.body.classList.contains('dark') ? '☀' : '☾';
    localStorage.setItem('kate-mu-theme', document.body.classList.contains('dark') ? 'dark' : 'light');
    setTimeout(drawChart, 30);
  });
  $('#rangeSelector').addEventListener('click', event => {
    const button = event.target.closest('button');
    if (!button) return;
    $$('#rangeSelector button').forEach(item => item.classList.toggle('active', item === button));
    loadTrend(button.dataset.range);
  });
  $('#menuButton').addEventListener('click', () => $('#sidebar').classList.toggle('open'));
  $('#sidebarOverlay').addEventListener('click', () => $('#sidebar').classList.remove('open'));
  $$('.nav-item').forEach(item => item.addEventListener('click', () => {
    $$('.nav-item').forEach(nav => nav.classList.remove('active'));
    item.classList.add('active');
    $('#sidebar').classList.remove('open');
  }));
  $('#pauseLogButton').addEventListener('click', event => {
    state.logsPaused = !state.logsPaused;
    event.currentTarget.textContent = state.logsPaused ? '▶ 继续滚动' : 'Ⅱ 暂停滚动';
    showToast(state.logsPaused ? '活动流已暂停' : '活动流已恢复');
    if (!state.logsPaused) loadEvents();
  });
  const viewAllButton = document.querySelector('.table-footer button');
  if (viewAllButton) {
    viewAllButton.addEventListener('click', () => {
      state.taskLimit = 200;
      viewAllButton.disabled = true;
      viewAllButton.textContent = '已显示全部任务';
      loadTasks();
    });
  }
  $('#refreshExports').addEventListener('click', () => Promise.allSettled([loadExports(), loadImportStatus()]));
  $('#exportFilter').addEventListener('change', event => {
    state.exportFilter = event.target.value;
    renderExports();
  });
  $('#cleanupEmptyExports').addEventListener('click', cleanupEmptyExportFiles);
  $('#uploadDropzone').addEventListener('click', () => $('#txtFileInput').click());
  $('#uploadDropzone').addEventListener('keydown', event => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      $('#txtFileInput').click();
    }
  });
  $('#uploadDropzone').addEventListener('dragover', event => {
    event.preventDefault();
    event.currentTarget.classList.add('dragging');
  });
  $('#uploadDropzone').addEventListener('dragleave', event => {
    event.currentTarget.classList.remove('dragging');
  });
  $('#uploadDropzone').addEventListener('drop', event => {
    event.preventDefault();
    event.currentTarget.classList.remove('dragging');
    handleFileSelect(event.dataTransfer.files);
  });
  $('#txtFileInput').addEventListener('change', event => {
    handleFileSelect(event.target.files);
    event.target.value = '';
  });
  $('#selectedFileQueue').addEventListener('click', event => {
    const removeButton = event.target.closest('[data-remove-selected-file]');
    if (!removeButton) return;
    state.selectedFiles.splice(Number(removeButton.dataset.removeSelectedFile), 1);
    renderSelectedFiles();
  });
  $('#uploadButton').addEventListener('click', uploadSelectedFiles);
  $('#credentialTextInput').addEventListener('input', updateCredentialLineCount);
  $('#credentialTextInput').addEventListener('keydown', event => {
    if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
      event.preventDefault();
      queueTextCredentials();
    }
  });
  $('#queueTextButton').addEventListener('click', queueTextCredentials);
  $('#exportTableBody').addEventListener('click', event => {
    const viewButton = event.target.closest('[data-view-file]');
    const downloadButton = event.target.closest('[data-download-file]');
    const deleteButton = event.target.closest('[data-delete-file]');
    if (viewButton) {
      openExportView(decodeURIComponent(viewButton.dataset.viewFile));
    } else if (downloadButton) {
      const name = decodeURIComponent(downloadButton.dataset.downloadFile);
      window.location.href = `/api/exports/content?file=${encodeURIComponent(name)}`;
    } else if (deleteButton) {
      deleteExportFile(decodeURIComponent(deleteButton.dataset.deleteFile), deleteButton);
    }
  });
  $('#exportModalClose').addEventListener('click', closeExportView);
  $('#exportModal').addEventListener('click', event => {
    if (event.target === $('#exportModal')) closeExportView();
  });
  window.addEventListener('resize', () => drawChart());
}

function init() {
  if (localStorage.getItem('kate-mu-theme') === 'dark') {
    document.body.classList.add('dark');
    $('#themeButton').textContent = '☀';
  }
  renderSteps();
  renderTasks();
  renderActivities();
  renderExports();
  renderImportStatus();
  renderSelectedFiles();
  updateCredentialLineCount();
  setTime();
  setServiceState(false, new Date());
  initEvents();
  initProxyEvents();
  loadProxySettings();
  refreshAll();
  setInterval(() => refreshAll({ silent: true }), 2000);
}

document.addEventListener('DOMContentLoaded', init);



// ── Proxy Settings & Management ──────────────────────────────────────────

async function loadProxySettings() {
  try {
    const data = await apiFetch('/api/settings/proxy');
    if (!data || !data.proxy) return;

    const proxy = data.proxy;
    const mode = proxy.mode || 'none';

    const modeRadios = $$('input[name="proxyMode"]');
    modeRadios.forEach(radio => {
      radio.checked = radio.value === mode;
    });

    if ($('#customProxyInput')) $('#customProxyInput').value = proxy.custom_proxy || '';
    if ($('#proxyFileInput')) $('#proxyFileInput').value = proxy.proxy_file || 'proxies.txt';
    if ($('#proxyApiUrlInput')) $('#proxyApiUrlInput').value = proxy.proxy_api_url || '';
    if ($('#proxyTimeoutInput')) $('#proxyTimeoutInput').value = proxy.proxy_timeout || 15;

    parseRawProxyToBuilder(proxy.custom_proxy || '');
    updateProxyModePanels(mode);
    updateProxyBadge(mode, data.loaded_count || 0);
  } catch (err) {
    console.warn('Failed to load proxy settings:', err);
  }
}

function updateProxyModePanels(mode) {
  const customPanel = $('#customProxyPanel');
  const filePanel = $('#fileProxyPanel');
  const apiPanel = $('#apiProxyPanel');

  if (customPanel) customPanel.style.display = mode === 'custom' ? 'flex' : 'none';
  if (filePanel) filePanel.style.display = mode === 'file' ? 'flex' : 'none';
  if (apiPanel) apiPanel.style.display = mode === 'api' ? 'flex' : 'none';
}

function updateProxyBadge(mode, loadedCount) {
  const pulse = $('#proxyPulse');
  const label = $('#proxyActiveLabel');
  if (!label) return;

  const modeNames = {
    none: '当前模式：直连 (未启用代理)',
    custom: '当前模式：自定义单节点代理',
    file: `当前模式：代理池文件 (已载入 ${loadedCount} 个)`,
    api: '当前模式：动态 API 代理'
  };

  label.textContent = modeNames[mode] || `当前模式：${mode}`;
  if (pulse) {
    pulse.className = 'pulse' + (mode === 'none' ? ' offline' : '');
  }
}

function parseRawProxyToBuilder(urlStr) {
  const raw = (urlStr || '').trim();
  if (!raw) {
    if ($('#builderHost')) $('#builderHost').value = '';
    if ($('#builderPort')) $('#builderPort').value = '';
    if ($('#builderUser')) $('#builderUser').value = '';
    if ($('#builderPass')) $('#builderPass').value = '';
    return;
  }

  let workStr = raw;
  let scheme = 'socks5';

  const matchScheme = raw.match(/^(https?|socks5h?):\/\//i);
  if (matchScheme) {
    scheme = matchScheme[1].toLowerCase();
    workStr = raw.substring(matchScheme[0].length);
  }

  if ($('#builderScheme')) $('#builderScheme').value = scheme;

  let auth = '';
  let hostPort = workStr;
  if (workStr.includes('@')) {
    [auth, hostPort] = workStr.split('@');
  }

  if (auth) {
    const [u, p] = auth.split(':');
    if ($('#builderUser')) $('#builderUser').value = u || '';
    if ($('#builderPass')) $('#builderPass').value = p || '';
  } else {
    if ($('#builderUser')) $('#builderUser').value = '';
    if ($('#builderPass')) $('#builderPass').value = '';
  }

  if (hostPort) {
    const [h, port] = hostPort.split(':');
    if ($('#builderHost')) $('#builderHost').value = h || '';
    if ($('#builderPort')) $('#builderPort').value = port || '';
  }
}

function syncBuilderToRawProxy() {
  const scheme = $('#builderScheme') ? $('#builderScheme').value : 'socks5';
  const host = $('#builderHost') ? $('#builderHost').value.trim() : '';
  const port = $('#builderPort') ? $('#builderPort').value.trim() : '';
  const user = $('#builderUser') ? $('#builderUser').value.trim() : '';
  const pass = $('#builderPass') ? $('#builderPass').value.trim() : '';

  if (!host && !port) return;

  let url = `${scheme}://`;
  if (user) {
    url += pass ? `${user}:${pass}@` : `${user}@`;
  }
  url += host;
  if (port) {
    url += `:${port}`;
  }

  if ($('#customProxyInput')) {
    $('#customProxyInput').value = url;
  }
}

async function saveProxySettings() {
  const modeRadio = $('input[name="proxyMode"]:checked');
  const mode = modeRadio ? modeRadio.value : 'none';

  const payload = {
    mode: mode,
    custom_proxy: $('#customProxyInput') ? $('#customProxyInput').value.trim() : '',
    proxy_file: $('#proxyFileInput') ? $('#proxyFileInput').value.trim() : 'proxies.txt',
    proxy_api_url: $('#proxyApiUrlInput') ? $('#proxyApiUrlInput').value.trim() : '',
    proxy_timeout: $('#proxyTimeoutInput') ? parseInt($('#proxyTimeoutInput').value, 10) || 15 : 15
  };

  try {
    const btn = $('#saveProxyBtn');
    if (btn) { btn.disabled = true; btn.textContent = '💾 保存中...'; }

    const res = await apiFetch('/api/settings/proxy', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    showToast(res.message || '代理配置已更新');
    updateProxyBadge(res.proxy.mode, res.loaded_count || 0);
  } catch (err) {
    showToast(`保存失败: ${err.message}`);
  } finally {
    const btn = $('#saveProxyBtn');
    if (btn) { btn.disabled = false; btn.textContent = '💾 保存代理配置'; }
  }
}

async function testProxySettings() {
  const modeRadio = $('input[name="proxyMode"]:checked');
  const mode = modeRadio ? modeRadio.value : 'none';
  const customProxy = $('#customProxyInput') ? $('#customProxyInput').value.trim() : '';

  const resBox = $('#testResultBox');
  if (!resBox) return;

  resBox.style.display = 'flex';
  resBox.className = 'test-result-box';
  resBox.innerHTML = '<span class="pulse"></span> 正在测试代理连通性...';

  const btn = $('#testProxyBtn');
  if (btn) { btn.disabled = true; btn.textContent = '⚡ 测试中...'; }

  try {
    const res = await apiFetch('/api/settings/proxy/test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        proxy_url: mode === 'custom' ? customProxy : undefined,
        timeout: 5
      })
    });

    if (res.ok) {
      res.className = 'test-result-box success';
      resBox.className = 'test-result-box success';
      resBox.innerHTML = `<strong>✓ ${escapeHtml(res.message || '代理连通正常')}</strong> <span>协议: ${escapeHtml(res.scheme)}</span> <span>节点: ${escapeHtml(res.host)}:${res.port}</span>`;
    } else {
      resBox.className = 'test-result-box error';
      resBox.innerHTML = `<strong>✕ 连通测试失败</strong> <span>${escapeHtml(res.error || '无法连接')}</span>`;
    }
  } catch (err) {
    resBox.className = 'test-result-box error';
    resBox.innerHTML = `<strong>✕ 测试请求失败</strong> <span>${escapeHtml(err.message)}</span>`;
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = '⚡ 测试代理连通性'; }
  }
}

function initProxyEvents() {
  $$('input[name="proxyMode"]').forEach(radio => {
    radio.addEventListener('change', event => {
      updateProxyModePanels(event.target.value);
    });
  });

  ['builderScheme', 'builderHost', 'builderPort', 'builderUser', 'builderPass'].forEach(id => {
    const el = $(`#${id}`);
    if (el) {
      el.addEventListener('input', syncBuilderToRawProxy);
      el.addEventListener('change', syncBuilderToRawProxy);
    }
  });

  const customInput = $('#customProxyInput');
  if (customInput) {
    customInput.addEventListener('input', event => {
      parseRawProxyToBuilder(event.target.value);
    });
  }

  $$('.preset-chip').forEach(chip => {
    chip.addEventListener('click', () => {
      const preset = chip.dataset.preset;
      if (preset && customInput) {
        customInput.value = preset;
        parseRawProxyToBuilder(preset);
        showToast(`已填入: ${preset}`);
      }
    });
  });

  const saveBtn = $('#saveProxyBtn');
  if (saveBtn) saveBtn.addEventListener('click', saveProxySettings);

  const testBtn = $('#testProxyBtn');
  if (testBtn) testBtn.addEventListener('click', testProxySettings);
}
