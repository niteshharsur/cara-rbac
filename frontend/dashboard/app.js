/* app.js - CARA-RBAC SPA Frontend Logic */

const API_BASE = window.location.origin + '/api/v1';

// Application State
const state = {
  token: localStorage.getItem('cara_jwt_token') || null,
  user: JSON.parse(localStorage.getItem('cara_user')) || null,
  activeScanID: null,
  scans: [],
  ratioChart: null,
  d3Simulation: null
};

// Document Elements
const els = {
  authSection: document.getElementById('auth-section'),
  appSection: document.getElementById('app-section'),
  loginForm: document.getElementById('login-form'),
  registerForm: document.getElementById('register-form'),
  toggleRegister: document.getElementById('toggle-register'),
  toggleLogin: document.getElementById('toggle-login'),
  logoutBtn: document.getElementById('logout-btn'),
  
  widgetAvatar: document.getElementById('widget-avatar'),
  widgetUsername: document.getElementById('widget-username'),
  widgetUserrole: document.getElementById('widget-userrole'),
  
  navScanDetails: document.getElementById('nav-scan-details'),
  navGraphView: document.getElementById('nav-graph-view'),
  navMinimizerView: document.getElementById('nav-minimizer-view'),
  
  btnNewScan: document.getElementById('btn-new-scan'),
  newScanPanel: document.getElementById('new-scan-panel'),
  newScanForm: document.getElementById('new-scan-form'),
  btnCancelNewScan: document.getElementById('btn-cancel-new-scan'),
  btnRefreshScans: document.getElementById('btn-refresh-scans'),
  scansListBody: document.getElementById('scans-list-body'),
  
  statCep: document.getElementById('stat-cep'),
  statSfp: document.getElementById('stat-sfp'),
  statRp: document.getElementById('stat-rp'),
  classificationsBody: document.getElementById('classifications-body'),
  
  originalYamlView: document.getElementById('original-yaml-view'),
  minimizedYamlView: document.getElementById('minimized-yaml-view'),
  btnDownloadRollback: document.getElementById('btn-download-rollback'),
  btnSyncGraph: document.getElementById('btn-sync-graph'),
  detailsDrawer: document.getElementById('details-drawer'),
  closeDrawerBtn: document.getElementById('close-drawer-btn'),
  drawerBodyContent: document.getElementById('drawer-body-content')
};

// --- AUTHENTICATION FLOWS ---

function checkAuth() {
  if (state.token) {
    els.authSection.style.display = 'none';
    els.appSection.style.display = 'flex';
    
    // Update user widget
    els.widgetUsername.textContent = state.user?.email || 'User';
    els.widgetUserrole.textContent = state.user?.role || 'Viewer';
    els.widgetAvatar.textContent = (state.user?.email || 'U').charAt(0).toUpperCase();
    
    loadScans();
  } else {
    els.authSection.style.display = 'flex';
    els.appSection.style.display = 'none';
  }
}

// Toggle register view
els.toggleRegister.addEventListener('click', (e) => {
  e.preventDefault();
  els.loginForm.style.display = 'none';
  els.registerForm.style.display = 'block';
  document.getElementById('auth-mode-subtitle').textContent = 'Create a security auditor account';
});

// Toggle login view
els.toggleLogin.addEventListener('click', (e) => {
  e.preventDefault();
  els.registerForm.style.display = 'none';
  els.loginForm.style.display = 'block';
  document.getElementById('auth-mode-subtitle').textContent = 'Access the security console';
});

// Register submission
els.registerForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = document.getElementById('reg-email').value;
  const password = document.getElementById('reg-password').value;
  const role = document.getElementById('reg-role').value;
  
  try {
    const res = await fetch(`${API_BASE}/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password, role })
    });
    
    if (!res.ok) throw new Error(await res.text() || 'Registration failed');
    
    alert('User registered successfully! Please sign in.');
    els.toggleLogin.click();
  } catch (err) {
    alert(err.message);
  }
});

// Login submission
els.loginForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = document.getElementById('login-email').value;
  const password = document.getElementById('login-password').value;
  
  try {
    const res = await fetch(`${API_BASE}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    
    if (!res.ok) throw new Error('Invalid email or password');
    const data = await res.json();
    
    state.token = data.token || data.access_token;
    state.user = { email, role: data.role || 'Auditor' };
    
    localStorage.setItem('cara_jwt_token', state.token);
    localStorage.setItem('cara_user', JSON.stringify(state.user));
    
    checkAuth();
  } catch (err) {
    alert(err.message);
  }
});

// Logout
els.logoutBtn.addEventListener('click', (e) => {
  e.preventDefault();
  state.token = null;
  state.user = null;
  localStorage.removeItem('cara_jwt_token');
  localStorage.removeItem('cara_user');
  location.reload();
});

// --- SPA VIEW ROUTING ---

document.querySelectorAll('.nav-item').forEach(item => {
  item.addEventListener('click', (e) => {
    e.preventDefault();
    const viewId = item.getAttribute('data-view');
    
    // Close details drawer on view change
    if (els.detailsDrawer) {
      els.detailsDrawer.classList.remove('open');
    }
    
    document.querySelectorAll('.view-section').forEach(view => {
      view.classList.remove('active');
    });
    document.querySelectorAll('.nav-item').forEach(nav => {
      nav.classList.remove('active');
    });
    
    document.getElementById(viewId).classList.add('active');
    item.classList.add('active');
    
    // Load view specific data
    if (viewId === 'graph-analysis-view') {
      renderGraph();
    } else if (viewId === 'rbac-minimizer-view') {
      loadMinimizationData();
    } else if (viewId === 'scan-details-view') {
      loadScanDetails();
    }
  });
});

// --- SCANS LIST MANAGEMENT ---

els.btnNewScan.addEventListener('click', () => {
  els.newScanPanel.style.display = 'block';
});

els.btnCancelNewScan.addEventListener('click', () => {
  els.newScanPanel.style.display = 'none';
});

els.btnRefreshScans.addEventListener('click', loadScans);

async function loadScans() {
  try {
    const res = await fetch(`${API_BASE}/scans`, {
      headers: { 'Authorization': `Bearer ${state.token}` }
    });
    if (!res.ok) throw new Error('Failed to fetch scans');
    const data = await res.json();
    const rawScans = Array.isArray(data) ? data : (data.scans || []);
    state.scans = rawScans.map(scan => ({
      ...scan,
      id: scan.id || scan.scan_id
    }));
    
    renderScansList(state.scans);
  } catch (err) {
    console.error(err);
  }
}

function renderScansList(scans) {
  els.scansListBody.innerHTML = '';
  if (scans.length === 0) {
    els.scansListBody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted);">No scan pipelines found. Register or launch a scan.</td></tr>`;
    return;
  }
  
  scans.forEach(scan => {
    const tr = document.createElement('tr');
    const statusBadge = getStatusBadge(scan.status);
    
    tr.innerHTML = `
      <td style="font-family: 'JetBrains Mono', monospace; font-size: 0.85rem;">${scan.id}</td>
      <td style="font-family: 'JetBrains Mono', monospace; font-size: 0.85rem;">${scan.application_id}</td>
      <td><span class="badge badge-secondary">${scan.mode}</span></td>
      <td>${statusBadge}</td>
      <td>${new Date(scan.created_at).toLocaleString()}</td>
      <td>
        <button class="btn btn-secondary btn-inspect" data-id="${scan.id}" style="padding: 0.4rem 0.8rem; font-size: 0.8rem;">Inspect</button>
      </td>
    `;
    els.scansListBody.appendChild(tr);
  });
  
  // Attach inspectors
  document.querySelectorAll('.btn-inspect').forEach(btn => {
    btn.addEventListener('click', () => {
      state.activeScanID = btn.getAttribute('data-id');
      
      // Show sidebar items for details
      els.navScanDetails.style.display = 'flex';
      els.navGraphView.style.display = 'flex';
      els.navMinimizerView.style.display = 'flex';
      
      // Go to details view
      els.navScanDetails.click();
    });
  });
}

function getStatusBadge(status) {
  switch (status) {
    case 'completed': return '<span class="badge badge-success">Completed</span>';
    case 'running': return '<span class="badge badge-warning">Running</span>';
    case 'failed': return '<span class="badge badge-danger">Failed</span>';
    default: return '<span class="badge badge-secondary">Pending</span>';
  }
}

els.newScanForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const appId = document.getElementById('scan-app-id').value;
  const mode = document.getElementById('scan-mode').value;
  const repo = document.getElementById('scan-repo-url').value;
  
  try {
    const res = await fetch(`${API_BASE}/scans`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${state.token}`
      },
      body: JSON.stringify({ application_id: appId, mode: mode, source_repo_url: repo })
    });
    
    if (!res.ok) throw new Error('Failed to launch scan');
    alert('Scan started successfully!');
    els.newScanPanel.style.display = 'none';
    loadScans();
  } catch (err) {
    alert(err.message);
  }
});

// --- SCAN DETAILS & RATIOS ---

async function loadScanDetails() {
  if (!state.activeScanID) return;
  
  // Update titles
  document.getElementById('details-title').textContent = `Scan Report: ${state.activeScanID.substring(0,8)}...`;
  
  try {
    // Fetch Scan Metadata for Risk Score
    const scanRes = await fetch(`${API_BASE}/scans/${state.activeScanID}`, {
      headers: { 'Authorization': `Bearer ${state.token}` }
    });
    if (scanRes.ok) {
      const scanData = await scanRes.json();
      const riskScore = parseFloat(scanData.app_risk_score || 0.0).toFixed(2);
      document.getElementById('stat-risk-score').textContent = riskScore;
    }

    // Start Live Log Polling
    startLiveTelemetryPolling(state.activeScanID);

    // 1. Fetch Summary statistics
    const summaryRes = await fetch(`${API_BASE}/scans/${state.activeScanID}/permissions/summary`, {
      headers: { 'Authorization': `Bearer ${state.token}` }
    });
    const summary = await summaryRes.json();
    
    // Summary map counts (backend returns counts wrapped inside 'counts' object)
    const counts = summary.counts || {};
    const cep = counts.CEP || summary.CEP || 0;
    const sfp = counts.SFP || summary.SFP || 0;
    const rp = (counts.RP || summary.RP || 0) + 
               (counts.SOP || summary.SOP || 0) + 
               (counts.DP || summary.DP || 0) + 
               (counts.DRP || summary.DRP || 0);
    
    els.statCep.textContent = cep;
    els.statSfp.textContent = sfp;
    els.statRp.textContent = rp;
    
    // Draw/update ratio chart
    renderChart(cep, sfp, rp);
    
    // 2. Fetch Classifications
    const classRes = await fetch(`${API_BASE}/scans/${state.activeScanID}/permissions/classifications`, {
      headers: { 'Authorization': `Bearer ${state.token}` }
    });
    const classes = await classRes.json();
    const classItems = Array.isArray(classes) ? classes : (classes.classifications || []);
    renderClassifications(classItems);
    
  } catch (err) {
    console.error('Error fetching scan report data:', err);
  }
}

function renderChart(cep, sfp, rp) {
  if (state.ratioChart) {
    state.ratioChart.destroy();
  }
  
  const ctx = document.getElementById('ratio-chart').getContext('2d');
  state.ratioChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Confirmed Excess (CEP)', 'Static FP (SFP)', 'Required (RP/SOP)'],
      datasets: [{
        data: [cep, sfp, rp],
        backgroundColor: ['#ef4444', '#f59e0b', '#10b981'],
        borderWidth: 0,
        hoverOffset: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          display: false
        }
      },
      cutout: '75%'
    }
  });
}

function renderClassifications(items) {
  state.classifications = items; // Store in state for drawer details
  els.classificationsBody.innerHTML = '';
  if (!items || items.length === 0) {
    els.classificationsBody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted);">No classification results found. Run FP engine.</td></tr>`;
    return;
  }
  
  items.forEach(item => {
    const tr = document.createElement('tr');
    
    // Get class label badge
    let classBadgeClass = 'badge-secondary';
    if (item.class === 'CEP') classBadgeClass = 'badge-danger';
    else if (item.class === 'SFP') classBadgeClass = 'badge-warning';
    else if (item.class === 'RP' || item.class === 'SOP') classBadgeClass = 'badge-success';
    
    const permString = `<code style="font-family: 'JetBrains Mono', monospace;">${item.verb}</code> on <code style="font-family: 'JetBrains Mono', monospace;">${item.resource}</code>`;
    
    tr.innerHTML = `
      <td>${permString}</td>
      <td><span class="badge ${classBadgeClass}">${item.class}</span></td>
      <td>${Math.round(item.confidence * 100)}%</td>
      <td style="font-weight: 600; color: ${item.threat_score > 0.6 ? 'var(--accent-danger)' : 'var(--text-main)'}">${item.threat_score}</td>
      <td style="font-size: 0.85rem; color: var(--text-muted);">${item.rationale}</td>
      <td style="display: flex; gap: 0.5rem; white-space: nowrap;">
        <button class="btn btn-secondary btn-details" data-id="${item.id}" style="padding: 0.3rem 0.6rem; font-size: 0.75rem;">Details</button>
        <button class="btn btn-secondary btn-ack" data-id="${item.id}" style="padding: 0.3rem 0.6rem; font-size: 0.75rem;">Acknowledge</button>
      </td>
    `;
    els.classificationsBody.appendChild(tr);
  });
  
  // Attach details triggers
  document.querySelectorAll('.btn-details').forEach(btn => {
    btn.addEventListener('click', () => {
      const id = btn.getAttribute('data-id');
      showDrawerDetails(id);
    });
  });

  // Attach acknowledge triggers
  document.querySelectorAll('.btn-ack').forEach(btn => {
    btn.addEventListener('click', async () => {
      const id = btn.getAttribute('data-id');
      try {
        const res = await fetch(`${API_BASE}/scans/${state.activeScanID}/permissions/${id}/acknowledge`, {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${state.token}` }
        });
        if (!res.ok) throw new Error('Acknowledge failed');
        alert('Permission acknowledged in security audit log trail.');
        loadScanDetails();
      } catch (err) {
        alert(err.message);
      }
    });
  });
}

async function showDrawerDetails(permId) {
  els.detailsDrawer.classList.add('open');
  els.drawerBodyContent.innerHTML = `
    <div style="text-align: center; padding: 3rem 0; color: var(--text-muted);">
      <span style="font-size: 1.5rem; display: block; margin-bottom: 0.5rem;">⏳</span> Fetching audit evidence logs...
    </div>
  `;

  const classification = state.classifications ? state.classifications.find(c => String(c.id) === String(permId)) : null;

  try {
    const res = await fetch(`${API_BASE}/scans/${state.activeScanID}/permissions/${permId}/evidence`, {
      headers: { 'Authorization': `Bearer ${state.token}` }
    });
    if (!res.ok) throw new Error('Failed to fetch evidence');
    const data = await res.json();
    const evidence = data.evidence || {};
    
    const evidenceStr = JSON.stringify(evidence, null, 2);
    
    let headerHtml = '';
    if (classification) {
      let classBadgeClass = 'badge-secondary';
      if (classification.class === 'CEP') classBadgeClass = 'badge-danger';
      else if (classification.class === 'SFP') classBadgeClass = 'badge-warning';
      else if (classification.class === 'RP' || classification.class === 'SOP') classBadgeClass = 'badge-success';

      headerHtml = `
        <div class="drawer-section">
          <div class="drawer-section-title">Permission Tuple</div>
          <div class="drawer-value-card">
            <code style="font-family: 'JetBrains Mono', monospace; font-size: 0.95rem; color: var(--accent-secondary);">${classification.verb}</code> on 
            <code style="font-family: 'JetBrains Mono', monospace; font-size: 0.95rem; color: var(--accent-secondary);">${classification.resource}</code>
          </div>
        </div>
        
        <div class="drawer-section" style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;">
          <div>
            <div class="drawer-section-title">Classification</div>
            <div class="drawer-value-card">
              <span class="badge ${classBadgeClass}" style="font-size: 0.8rem; padding: 0.35rem 0.75rem;">${classification.class}</span>
            </div>
          </div>
          <div>
            <div class="drawer-section-title">Threat Score</div>
            <div class="drawer-value-card" style="font-weight: 600; color: ${classification.threat_score > 0.6 ? 'var(--accent-danger)' : 'var(--text-main)'}">
              ${classification.threat_score}
            </div>
          </div>
        </div>

        <div class="drawer-section">
          <div class="drawer-section-title">Confidence & Scope</div>
          <div class="drawer-value-card" style="display: flex; justify-content: space-between; font-size: 0.9rem;">
            <span>Confidence: <strong>${Math.round(classification.confidence * 100)}%</strong></span>
            <span>Scope: <span class="badge badge-secondary" style="text-transform: capitalize;">${classification.scope}</span></span>
          </div>
        </div>

        <div class="drawer-section">
          <div class="drawer-section-title">Audit Rationale</div>
          <div class="drawer-value-card" style="line-height: 1.5; font-size: 0.9rem; color: var(--text-main);">
            ${classification.rationale}
          </div>
        </div>
      `;
    }

    els.drawerBodyContent.innerHTML = `
      ${headerHtml}
      <div class="drawer-section">
        <div class="drawer-section-title">Raw Logs & Evidence</div>
        <pre class="drawer-code-block">${escapeHTML(evidenceStr)}</pre>
      </div>
    `;
  } catch (err) {
    els.drawerBodyContent.innerHTML = `
      <div style="color: var(--accent-danger); padding: 1rem; border: 1px dashed var(--accent-danger); border-radius: 8px; font-size: 0.9rem;">
        <strong>Error</strong>: ${err.message}
      </div>
    `;
  }
}

function escapeHTML(str) {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// --- D3 GRAPH VISUALIZATION ---

async function renderGraph() {
  if (!state.activeScanID) return;
  
  const container = document.getElementById('d3-graph');
  const width = container.clientWidth || 800;
  const height = container.clientHeight || 500;
  
  // Clear previous SVG contents
  d3.select('#d3-graph').selectAll('*').remove();
  
  try {
    const res = await fetch(`${API_BASE}/scans/${state.activeScanID}/graph/permissions`, {
      headers: { 'Authorization': `Bearer ${state.token}` }
    });
    if (!res.ok) throw new Error('No graph link data found');
    const rawData = await res.json();
    
    // Normalize nodes & links to flat format required by D3
    const nodes = (rawData.nodes || []).map(n => {
      if (n.id && n.type) return n;
      const props = n.data || {};
      const labels = n.labels || [];
      const type = labels[0] || 'Unknown';
      return {
        id: props.id || props.name || (props.verb + ':' + props.resource),
        name: props.name || (props.verb + ':' + props.resource),
        type: type,
        namespace: props.namespace || props.scope,
        role: props.service_account,
        ...props
      };
    });

    const links = (rawData.links || rawData.edges || []).map(l => {
      if (!l.source || !l.target) return null;
      return {
        source: typeof l.source === 'object' ? (l.source.id || l.source.name || l.source) : l.source,
        target: typeof l.target === 'object' ? (l.target.id || l.target.name || l.target) : l.target,
        type: l.type || l.rel_type || 'USES_SA',
        ...l.properties
      };
    }).filter(Boolean);

    const data = { nodes, links };
    
    if (!data.nodes || data.nodes.length === 0) {
      d3.select('#d3-graph')
        .append('text')
        .attr('x', width / 2)
        .attr('y', height / 2)
        .attr('text-anchor', 'middle')
        .attr('fill', '#9ca3af')
        .text('No active graph nodes synced. Please Sync to Neo4j.');
      return;
    }
    
    const svg = d3.select('#d3-graph')
      .attr('viewBox', [0, 0, width, height]);
      
    // Set up forces simulation
    const simulation = d3.forceSimulation(data.nodes)
      .force('link', d3.forceLink(data.links).id(d => d.id).distance(120))
      .force('charge', d3.forceManyBody().strength(-150))
      .force('center', d3.forceCenter(width / 2, height / 2));
      
    state.d3Simulation = simulation;
    
    // Draw relationships links
    const link = svg.append('g')
      .selectAll('line')
      .data(data.links)
      .join('line')
      .attr('class', 'link');
      
    // Draw nodes
    const node = svg.append('g')
      .selectAll('g')
      .data(data.nodes)
      .join('g')
      .attr('class', 'node')
      .call(drag(simulation));
      
    // Nodes backgrounds
    node.append('circle')
      .attr('r', d => d.type === 'Pod' ? 14 : 9)
      .attr('fill', d => {
        if (d.type === 'Pod') return '#8b5cf6';         // Primary Purple
        if (d.type === 'ServiceAccount') return '#06b6d4'; // Cyan
        if (d.type === 'Role') return '#f59e0b';           // Warning Amber
        return '#ef4444';                                 // Secrets Red
      })
      .attr('stroke', '#07080a')
      .attr('stroke-width', 2);
      
    // Labels
    node.append('text')
      .attr('x', 14)
      .attr('y', 4)
      .text(d => d.name || d.id);
      
    // Hover details
    node.on('mouseover', (event, d) => {
      const details = document.getElementById('node-details-panel');
      details.innerHTML = `
        <div style="text-align: left; padding: 0.5rem;">
          <h4 style="color: var(--text-main); margin-bottom: 0.5rem; border-bottom: 1px solid var(--panel-border); padding-bottom: 0.25rem;">Node Properties</h4>
          <p><strong>Name</strong>: ${d.name || d.id}</p>
          <p><strong>Type</strong>: <span class="badge badge-secondary">${d.type}</span></p>
          ${d.namespace ? `<p><strong>Namespace</strong>: ${d.namespace}</p>` : ''}
          ${d.role ? `<p><strong>SA Role</strong>: ${d.role}</p>` : ''}
        </div>
      `;
    });
    
    simulation.on('tick', () => {
      link
        .attr('x1', d => d.source.x)
        .attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x)
        .attr('y2', d => d.target.y);
        
      node
        .attr('transform', d => `translate(${d.x},${d.y})`);
    });
    
  } catch (err) {
    console.error(err);
  }
}

// Drag functionality for D3
function drag(simulation) {
  function dragstarted(event) {
    if (!event.active) simulation.alphaTarget(0.3).restart();
    event.subject.fx = event.subject.x;
    event.subject.fy = event.subject.y;
  }
  
  function dragged(event) {
    event.subject.fx = event.x;
    event.subject.fy = event.y;
  }
  
  function dragended(event) {
    if (!event.active) simulation.alphaTarget(0);
    event.subject.fx = null;
    event.subject.fy = null;
  }
  
  return d3.drag()
    .on('start', dragstarted)
    .on('drag', dragged)
    .on('end', dragended);
}

// Sync Postgres observations with Neo4j Graph
els.btnSyncGraph.addEventListener('click', async () => {
  if (!state.activeScanID) return;
  try {
    const res = await fetch(`${API_BASE}/scans/${state.activeScanID}/graph/sync`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${state.token}` }
    });
    if (!res.ok) throw new Error('Sync failed');
    alert('PostgreSQL records successfully synchronized to Neo4j graph nodes.');
    renderGraph();
  } catch (err) {
    alert(err.message);
  }
});

// --- RBAC MINIMIZATION PANELS ---

async function loadMinimizationData() {
  if (!state.activeScanID) return;
  
  try {
    const res = await fetch(`${API_BASE}/scans/${state.activeScanID}/minimization`, {
      headers: { 'Authorization': `Bearer ${state.token}` }
    });
    if (!res.ok) throw new Error('Minimization result not generated. Trigger M7 minimizer.');
    const data = await res.json();
    
    // Update YAML views
    els.originalYamlView.textContent = data.original_yaml || '# No original manifest recorded.';
    els.minimizedYamlView.textContent = data.minimized_yaml || '# No minimized manifest generated.';
    
    // Display metadata panel
    const metaPanel = document.getElementById('minimization-meta-panel');
    if (metaPanel) {
      metaPanel.style.display = 'block';
      
      const badge = document.getElementById('val-status-badge');
      const details = document.getElementById('val-details-text');
      const recsList = document.getElementById('splitting-recs-list');
      
      if (badge && details) {
        badge.textContent = (data.validation_status || 'skipped').toUpperCase();
        badge.className = 'badge ' + (data.validation_status === 'passed' ? 'badge-success' : (data.validation_status === 'failed' ? 'badge-danger' : 'badge-secondary'));
        details.textContent = data.validation_details || 'No details available.';
      }
      
      if (recsList) {
        recsList.innerHTML = '';
        const recs = data.role_splitting_suggestions;
        if (recs && recs.length > 0) {
          recs.forEach(rec => {
            const li = document.createElement('li');
            li.innerHTML = `<strong>ServiceAccount:</strong> <code style="font-family: monospace;">${rec.service_account}</code> shared by ${rec.sharing_pods.join(', ')}.<br><span style="color: var(--accent-warning);">${rec.action}</span>`;
            recsList.appendChild(li);
          });
        } else {
          recsList.innerHTML = '<li>No ServiceAccount sharing issues detected. Workload contexts are isolated.</li>';
        }
      }
    }
    
  } catch (err) {
    els.originalYamlView.textContent = `# Error: ${err.message}`;
    els.minimizedYamlView.textContent = `# Error: ${err.message}`;
  }
}

// Rollback Script download
els.btnDownloadRollback.addEventListener('click', async () => {
  if (!state.activeScanID) return;
  window.open(`${API_BASE}/scans/${state.activeScanID}/minimization/rollback?token=${state.token}`);
});

// Apply to cluster
els.btnApplyCluster.addEventListener('click', async () => {
  if (!state.activeScanID) return;
  if (!confirm('Are you sure you want to deploy the minimized Role bindings to the live Kubernetes cluster? This will update cluster RBAC access.')) return;
  
  try {
    const res = await fetch(`${API_BASE}/scans/${state.activeScanID}/minimization/apply`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${state.token}`
      },
      body: JSON.stringify({ dry_run: false })
    });
    
    if (!res.ok) throw new Error('Apply failed');
    const data = await res.json();
    
    alert(`Successfully applied minimized Role settings to cluster.\nStatus: ${data.status}`);
  } catch (err) {
    alert(err.message);
  }
});

// Close details drawer
els.closeDrawerBtn.addEventListener('click', () => {
  els.detailsDrawer.classList.remove('open');
});

let livePollInterval = null;

function startLiveTelemetryPolling(scanID) {
  if (livePollInterval) clearInterval(livePollInterval);
  
  const container = document.getElementById('falco-log-container');
  if (!container) return;
  
  let lastCount = 0;
  
  livePollInterval = setInterval(async () => {
    if (state.activeScanID !== scanID) {
      clearInterval(livePollInterval);
      return;
    }
    try {
      const res = await fetch(`${API_BASE}/scans/${scanID}/runtime/observations`, {
        headers: { 'Authorization': `Bearer ${state.token}` }
      });
      if (!res.ok) return;
      const data = await res.json();
      const obs = data.observations || data || [];
      
      if (obs.length > lastCount) {
        container.innerHTML = '';
        const latest = obs.slice(-10);
        latest.forEach(o => {
          const div = document.createElement('div');
          div.textContent = `[${new Date(o.last_observed_at || Date.now()).toLocaleTimeString()}] runtime access: SA=${o.source_role || 'default'} verb=${o.verb} resource=${o.resource} namespace=${o.scope || 'default'} frequency=${o.execution_frequency || 0.0}/day`;
          container.appendChild(div);
        });
        container.scrollTop = container.scrollHeight;
        lastCount = obs.length;
      }
    } catch (err) {
      console.error('Error fetching live logs:', err);
    }
  }, 4000);
}

// Start checks
checkAuth();
