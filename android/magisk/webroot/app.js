/* SPDX-License-Identifier: GPL-2.0 */
/* app.js — eBPF-Split KernelSU WebUI 前端
 *
 * 后端是运行期脚本 /data/adb/split/scripts/webuiapi.sh（root，经 ksu.exec 调用）。
 * 本文件只做展示与组装参数，不透传任意 shell。
 *
 * 特性（v1.2.x WebUI 完善）：
 *  - 状态页：运行状态卡补 TUN ifindex / splitd PID / 存活守护 / 运行时长；
 *    新增"环境信息"卡（内核/系统/SELinux/设备）；stats 增量速率 + 异常着色。
 *  - 参数页：get-config 解析的"当前生效配置摘要"卡。
 *  - 规则页：在线规则按 proxy/direct 计数展示。
 *  - 状态面板每 5s 轮询（仅激活时），含 env。
 */

import { exec, toast } from './kernelsu.js';

const API = '/data/adb/split/scripts/webuiapi.sh';

const $ = (id) => document.getElementById(id);

/* 内核统计段的中文标签（与 daemon ctl_stats 的 names[] 对应） */
const STAT_LABELS = {
  total: '总包数', direct_cn: '直连·CN', direct_rule: '直连·规则',
  proxy: '代理', skip_uid: '白名单', parse_err: '解析错误',
  redirect_err: '重定向错误', dropped: '丢弃', miss_tun: 'TUN缺失',
  direct_v6: '直连·v6',
};
/* 增长即"流量在走"的计数（绿色）；异常计数（红色，正常应为 0） */
const STAT_GROW_OK = new Set(['direct_cn', 'direct_rule', 'proxy', 'direct_v6']);
const STAT_DANGER = new Set(['parse_err', 'redirect_err', 'dropped', 'miss_tun']);

/* ---------- 工具 ---------- */
async function callApi(args) {
  const { errno, stdout, stderr } = await exec(`${API} ${args}`);
  if (errno !== 0) {
    console.error(stderr);
    return { err: true, text: stderr || stdout || `errno=${errno}` };
  }
  return { err: false, text: stdout };
}

function showToast(msg) {
  try { toast(msg); } catch (_) { /* manager 不支持则忽略 */ }
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/* key=value 逐行解析（env / mihomo-status 通用） */
function parseKeyValues(text) {
  const out = {};
  (text || '').split('\n').forEach(l => {
    const i = l.indexOf('=');
    if (i > 0) out[l.slice(0, i).trim()] = l.slice(i + 1).trim();
  });
  return out;
}

function setStatusDot(on) {
  const dot = $('st-dot');
  dot.dataset.on = on;
  dot.textContent = on === 'on' ? '运行中' : (on === 'off' ? '未运行' : '未知');
}

/* ---------- 版本（顶栏） ---------- */
async function loadVersion() {
  const r = await callApi('version');
  const m = (r.text || '').match(/SPLIT_VERSION=(\S+)/);
  $('renderer').textContent = m ? `v${m[1]}` : '—';
}

/* ---------- 状态 / 计数 ---------- */
async function loadStatus() {
  const r = await callApi('status');
  const body = r.err ? r.text : r.text.trim();
  const progfd = (body.match(/prog_fd=(\d+)/) || [])[1];
  const attached = (body.match(/attached=(\d+)/) || [])[1];
  const tun = (body.match(/tun=(\d+)/) || [])[1];
  const cnip4 = (body.match(/cnip4=(\d+)/) || [])[1];
  const cnip6 = (body.match(/cnip6=(\d+)/) || [])[1];
  const hijack = (body.match(/hijack=(-?\d+)/) || [])[1];
  setStatusDot((progfd && progfd !== '-1') || /^OK/.test(body) ? 'on' : 'off');
  $('st-progfd').textContent = progfd || '—';
  $('st-attached').textContent = (attached === undefined) ? '—' : attached;
  $('st-cnip').textContent = (cnip4 === undefined) ? '—' : `${cnip4}/${cnip6}`;
  const tunEl = $('st-tun');
  if (tun === '0') {
    tunEl.textContent = '0（缺失，流量放行）';
    tunEl.className = 'v mono v-warn';
  } else if (tun !== undefined) {
    tunEl.textContent = tun;
    tunEl.className = 'v mono';
  } else {
    tunEl.textContent = '—';
    tunEl.className = 'v mono';
  }
  const hijackEl = $('st-hijack');
  if (hijack === '1') {
    hijackEl.textContent = '⚠ 已接管（eBPF 失效）';
    hijackEl.className = 'v v-bad';
  } else if (hijack === '0') {
    hijackEl.textContent = '正常';
    hijackEl.className = 'v v-ok';
  } else {
    hijackEl.textContent = hijack === '-1' ? '检测失败' : '—';
    hijackEl.className = 'v';
  }
  const warns = body.split('\n')
    .map(l => l.trim())
    .filter(l => /^WARN /.test(l))
    .map(l => `<div class="warn-line">⚠ ${escapeHtml(l.slice(5))}</div>`)
    .join('');
  $('st-warns').innerHTML = warns;
}

async function loadEnv() {
  const r = await callApi('env');
  const m = parseKeyValues(r.err ? '' : r.text);
  $('env-kernel').textContent = m.kernel || '—';
  $('env-arch').textContent = m.arch || '—';
  $('env-android').textContent = m.android || '—';
  $('env-sdk').textContent = m.sdk || '—';
  $('env-device').textContent = m.device || '—';
  const sel = $('env-selinux');
  sel.textContent = m.selinux || '—';
  sel.className = 'v' + (m.selinux === 'Permissive' ? ' v-warn' : '');
  $('st-pid').textContent = m.splitd_pid || '—';
  $('st-watchdog').textContent = m.watchdog === '1' ? '守护中' : (m.watchdog === '0' ? '未运行' : '—');
  $('st-uptime').textContent = m.uptime || '—';
}

async function loadMihomo() {
  const r = await callApi('mihomo-status');
  const m = parseKeyValues(r.err ? '' : r.text);
  const status = m.status;
  const dot = $('mh-dot');
  dot.dataset.on = (status === 'running') ? 'on' : (status === 'stopped' ? 'off' : 'unknown');
  dot.textContent = status === 'running' ? '运行中'
    : (status === 'stopped' ? '未运行' : (status === 'no-binary' ? '无二进制' : '未知'));
  $('mh-status').textContent = (status === 'running' || status === 'stopped')
    ? status : (status || '—');
  $('mh-pid').textContent = m.pid || '—';
  $('mh-ver').textContent = m.ver || '—';
  $('mh-log').textContent = m.log || '—';
}

/* ---------- 内核计数（含增量速率） ---------- */
let statPrev = {};      // 上一轮各计数（增量速率基准）
let statPrevAt = 0;     // 上一轮拉取时刻（performance.now）

async function loadStats() {
  const r = await callApi('stats');
  const box = $('stats-body');
  if (r.err) {
    box.innerHTML = `<span class="v dim">${escapeHtml(r.text)}</span>`;
    $('st-updated').textContent = '';
    return;
  }
  const lines = r.text.split('\n')
    .map(l => l.trim())
    .filter(l => /^[A-Za-z_]+\s+\d+/.test(l));
  if (!lines.length) {
    box.innerHTML = '<span class="v dim">暂无内核算统计（splitd 未运行或 map 空）</span>';
    $('st-updated').textContent = '';
    return;
  }
  const now = performance.now();
  const dt = statPrevAt ? (now - statPrevAt) / 1000 : 0;
  box.innerHTML = lines.map(l => {
    const m = l.split(/\s+/);
    const key = m[0];
    const val = parseInt(m[1], 10);
    /* 增量速率：与上一轮对比；计数器回退（daemon 重启）显示 ↻ */
    let rate = '';
    if (statPrevAt && statPrev[key] !== undefined) {
      const d = val - statPrev[key];
      if (d > 0 && dt > 0) rate = `+${(d / dt).toFixed(1)}/s`;
      else if (d < 0) rate = '↻ 已重置';
    }
    const cls = STAT_DANGER.has(key)
      ? (val > 0 ? 'bad' : 'ok')
      : (STAT_GROW_OK.has(key) && val > 0 ? 'ok' : '');
    return `<div class="stat-chip ${cls}">` +
      `<span class="sc-label">${escapeHtml(STAT_LABELS[key] || key)}</span>` +
      `<span class="sc-val">${val}</span>` +
      (rate ? `<span class="sc-rate">${escapeHtml(rate)}</span>` : '') +
      `</div>`;
  }).join('');
  statPrev = {};
  lines.forEach(l => {
    const m = l.split(/\s+/);
    statPrev[m[0]] = parseInt(m[1], 10);
  });
  statPrevAt = now;
  $('st-updated').textContent = `更新于 ${new Date().toLocaleTimeString()}`;
}

/* ---------- 日志 ---------- */
async function loadLog() {
  const which = $('log-which').value;
  const keep = $('log-body');
  const scrollAtBottom = (keep.scrollHeight - keep.scrollTop - keep.clientHeight) < 40;
  const r = await callApi(`get-log ${which} 200`);
  keep.textContent = r.err ? r.text : r.text;
  if (scrollAtBottom) keep.scrollTop = keep.scrollHeight;
}

// 自动刷新轮询句柄
let statTimer = 0, logTimer = 0;
function startPolling() {
  if (statTimer) return;
  // 状态/统计/mihomo/env 每 5 秒刷新；仅在状态面板激活时轮询
  statTimer = setInterval(() => {
    if (document.getElementById('panel-status').classList.contains('active')) {
      Promise.all([loadStatus(), loadStats(), loadMihomo(), loadEnv()]);
    }
  }, 5000);
}
function bindLogActions() {
  $('log-refresh').addEventListener('click', loadLog);
  $('log-auto').addEventListener('change', e => {
    if (e.target.checked && !logTimer) {
      logTimer = setInterval(() => {
        if (document.getElementById('panel-logs').classList.contains('active')) loadLog();
      }, 5000);
    } else if (!e.target.checked && logTimer) {
      clearInterval(logTimer);
      logTimer = 0;
    }
  });
  // 进日志面板即手拉一次（bindTabs 统一挂 tab 点击，此处只管本面板动作）
  if ($('log-auto').checked) {
    logTimer = setInterval(() => {
      if (document.getElementById('panel-logs').classList.contains('active')) loadLog();
    }, 5000);
  }
}

/* ---------- 规则 ---------- */
function validCidr(input) {
  const s = input.trim();
  if (!/^[0-9a-fA-F:.\/]+$/.test(s)) return false;
  return /\/\d{1,3}$/.test(s);
}

async function ruleAction(kind) {
  const cidr = $('rule-cidr').value.trim();
  const type = $('rule-type').value;
  if (!validCidr(cidr)) {
    showToast('CIDR 格式无效（需带前缀长度，如 1.2.3.0/24）');
    return;
  }
  // 单引号包裹 + shell 侧仅取整段参数，天然防命令注入
  const r = await callApi(`${kind}-rule '${cidr}' ${type}`);
  showToast(r.err ? `失败: ${r.text}` : `${kind === 'add' ? '加入' : '删除'}完成`);
  console.log('[rule]', r.text);
  loadRules();
}

/* 在线规则列表（daemon list-rules：逐行 "proxy <cidr>" / "direct <cidr>"） */
async function loadRules() {
  const box = $('rules-body');
  const r = await callApi('list-rules');
  if (r.err) {
    box.innerHTML = `<span class="v dim">${escapeHtml(r.text)}</span>`;
    $('rules-count').textContent = '';
    return;
  }
  const items = r.text.split('\n')
    .map(l => l.trim())
    .filter(l => /^(proxy|direct)\s+\S+/.test(l));
  if (!items.length) {
    box.innerHTML = '<span class="v dim">暂无在线规则（配置中的 proxy4/6、direct4/6 在此展示）</span>';
    $('rules-count').textContent = '';
    return;
  }
  let nProxy = 0, nDirect = 0;
  box.innerHTML = items.map(l => {
    const sp = l.indexOf(' ');
    const type = l.slice(0, sp);
    const cidr = l.slice(sp + 1).trim();
    if (type === 'proxy') nProxy++; else nDirect++;
    return `<div class="rule-item rule-${type}">` +
      `<span class="rule-type">${type}</span>` +
      `<span class="rule-cidr">${escapeHtml(cidr)}</span>` +
      `<button class="rule-del" data-cidr="${escapeHtml(cidr)}" data-type="${type}">删除</button>` +
      `</div>`;
  }).join('');
  $('rules-count').textContent = `proxy ${nProxy} · direct ${nDirect}`;
  box.querySelectorAll('.rule-del').forEach(btn => {
    btn.addEventListener('click', async () => {
      const r2 = await callApi(`del-rule '${btn.dataset.cidr}' ${btn.dataset.type}`);
      showToast(r2.err ? `删除失败: ${r2.text}` : '已删除');
      console.log('[rule-del]', r2.text);
      loadRules();
    });
  });
}

/* ---------- 配置 ---------- */
async function loadConfig() {
  const r = await callApi('get-config');
  $('cfg-editor').value = r.err ? `# 读取失败: ${r.text}` : r.text;
  return r.err ? '' : r.text;   // 供摘要解析复用
}

/* 极简 YAML 子集解析 → flat["section.key"] / lists["section.key"] */
function parseMiniYaml(text) {
  const flat = {};
  const lists = {};
  let section = '';
  let listKey = null;
  const SECTIONS = ['ifaces', 'default', 'rules', 'cnip'];
  for (const raw of (text || '').split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    if (line.startsWith('- ')) {
      if (listKey) (lists[listKey] = lists[listKey] || []).push(line.slice(2).trim());
      continue;
    }
    const m = line.match(/^([A-Za-z0-9_]+):\s*(.*)$/);
    if (!m) continue;
    const key = m[1];
    const val = m[2].replace(/\s*#.*$/, '').trim();
    if (val === '') {
      // 空值行：内置 section 名归入 section；其它视为列表头
      if (SECTIONS.includes(key)) { section = key; listKey = null; }
      else { listKey = section ? `${section}.${key}` : key; flat[listKey] = ''; }
      continue;
    }
    flat[section ? `${section}.${key}` : key] = val;
    listKey = null;
  }
  return { flat, lists };
}

const pathBase = (p) => String(p || '').split('/').pop() || p;

/* 从配置文本生成摘要行 [label, value, cls?] */
function summarizeConfig(text) {
  const { flat, lists } = parseMiniYaml(text);
  const n = (k) => (lists[k] || []).length;
  const rows = [];
  rows.push(['代理设备', flat['tun_device'] || '—']);
  const auto = flat['ifaces.attach_auto'];
  rows.push(['挂载范围', auto === 'false'
    ? `手动（${n('ifaces.attach_list')} 个）`
    : `自动（exclude ${n('ifaces.exclude')} 项）`]);
  const verdict = flat['default.verdict'];
  const v6 = flat['default.ipv6'] === 'false' ? '不参与' : '参与';
  rows.push(['默认判定', `${verdict === 'direct' ? '直连' : '代理'} · v6 ${v6}`]);
  rows.push(['强制代理 CIDR', `${n('rules.proxy_cidr4')}+${n('rules.proxy_cidr6')}`]);
  rows.push(['强制直连 CIDR', `${n('rules.direct_cidr4')}+${n('rules.direct_cidr6')}`]);
  const uids = lists['rules.skip_uid'] || [];
  rows.push(['skip_uid', uids.length ? uids.join(' ') : '—']);
  rows.push(['CNIP v4', pathBase(flat['cnip.path_v4']) || '未配置']);
  rows.push(['CNIP v6', pathBase(flat['cnip.path_v6']) || '未配置']);
  const upd = flat['cnip.auto_update_hours'];
  rows.push(['自动更新', upd ? `${upd} 小时` : '关闭']);
  if (flat['debug'] === 'true') rows.push(['调试模式', '开', 'v-warn']);
  return rows;
}

async function loadCfgSummary() {
  const text = await loadConfig();   // 复用一次拉取
  const box = $('cfg-summary');
  if (!text) { box.innerHTML = '<span class="v dim">无法读取配置</span>'; return; }
  box.innerHTML = summarizeConfig(text)
    .map(([k, v, cls]) => `<span class="k">${escapeHtml(k)}</span>` +
      `<span class="v mono ${cls || ''}">${escapeHtml(v)}</span>`)
    .join('');
}

function encodeToB64(str) {
  const bytes = new TextEncoder().encode(str);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

async function saveConfig() {
  const btn = $('cfg-save');
  btn.disabled = true;   // 防重复提交：保存期间禁用
  try {
    const b64 = encodeToB64($('cfg-editor').value);
    const r = await callApi(`save-config ${b64}`);
    $('cfg-result').textContent = r.text;
    showToast(r.err ? '保存失败' : '保存并 reload 完成');
    if (!r.err) { await loadCfgSummary(); loadRules(); }  // 落盘后摘要/在线规则同步
  } finally {
    btn.disabled = false;
  }
}

async function validateConfig() {
  const btn = $('cfg-validate');
  btn.disabled = true;
  try {
    const b64 = encodeToB64($('cfg-editor').value);
    const r = await callApi(`validate-config ${b64}`);
    $('cfg-result').textContent = r.text;
    showToast(r.err ? '校验未通过' : '校验通过');
  } finally {
    btn.disabled = false;
  }
}

/* ---------- 事件 ---------- */
function activateTab(name) {
  document.querySelectorAll('.tab').forEach(b => b.classList.toggle('active', b.dataset.tab === name));
  document.querySelectorAll('.panel').forEach(p => p.classList.toggle('active', p.id === `panel-${name}`));
}

function bindTabs() {
  document.querySelectorAll('.tab').forEach(btn => {
    btn.addEventListener('click', () => {
      activateTab(btn.dataset.tab);
      if (btn.dataset.tab === 'logs') loadLog();
    });
  });
  // mihomo 卡里的快捷跳转（查看日志 / 开关）
  document.querySelectorAll('.jump[data-tab]').forEach(a => {
    a.addEventListener('click', () => {
      activateTab(a.dataset.tab);
      if (a.dataset.tab === 'logs') loadLog();
    });
  });
}

/* 状态面板全量刷新（含手动"刷新"按钮与开关操作后） */
function refreshStatusPanel() {
  return Promise.all([loadStatus(), loadStats(), loadMihomo(), loadEnv()]);
}

function bindActions() {
  bindLogActions();
  startPolling();
  $('st-refresh').addEventListener('click', () => {
    refreshStatusPanel();
    loadVersion();
  });
  $('rule-add').addEventListener('click', () => ruleAction('add'));
  $('rule-del').addEventListener('click', () => ruleAction('del'));
  $('rules-refresh').addEventListener('click', loadRules);
  $('cfg-load').addEventListener('click', async () => {
    const text = await loadConfig();
    if (text) loadCfgSummary();
  });
  $('cfg-save').addEventListener('click', saveConfig);
  $('cfg-validate').addEventListener('click', validateConfig);

  // 守护进程动作：执行后回显输出并刷新状态面板（让结果立即可见）
  const btnHit = b => b.addEventListener('click', async () => {
    const r = await callApi(b.dataset.cmd);
    $('act-result').textContent = r.text;
    console.log('[daemon]', b.dataset.cmd, r.text);
    await refreshStatusPanel();
    if (!r.err && b.dataset.msg) showToast(b.dataset.msg);
    if (b.dataset.cmd === 'reload' || b.dataset.cmd === 'reload-cnip') loadCfgSummary();
  });
  btnHit($('act-start'));
  btnHit($('act-stop'));
  btnHit($('act-reload'));
  btnHit($('act-reload-cnip'));
  btnHit($('act-update-cnip'));

  const btnMihomo = (b, okMsg) => b.addEventListener('click', async () => {
    const r = await callApi(b.dataset.cmd);
    $('act-result').textContent = r.text;
    showToast(r.err ? r.text : okMsg);
    loadMihomo();
    loadEnv();
  });
  btnMihomo($('act-mihomo-start'), 'mihomo 启动完成');
  btnMihomo($('act-mihomo-stop'), 'mihomo 已停止');
}

async function init() {
  bindTabs();
  bindActions();
  await Promise.all([
    refreshStatusPanel(), loadCfgSummary(), loadRules(), loadVersion(),
  ]);
}

init();
