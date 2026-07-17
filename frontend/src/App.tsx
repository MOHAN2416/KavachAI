import React, { useState, useEffect, useRef } from 'react';

// API Response Interfaces
interface User {
  username: string;
  role: 'admin' | 'viewer';
}

interface LatestSnapshot {
  id: number;
  captured_at: string;
  http_status: number | null;
  fetch_error: string | null;
  visual_changed: number;
  text_changed: number;
}

interface Asset {
  id: number;
  name: string;
  url: string;
  is_active: number;
  interval_seconds: number;
  created_at: string;
  parent_asset_id: number | null;
  latest_snapshot: LatestSnapshot | null;
  vuln_state: string[];
}

interface Alert {
  id: number;
  asset_id: number;
  snapshot_id: number;
  kind: 'change' | 'vuln' | 'availability';
  title: string;
  severity: 'high' | 'medium' | 'low' | 'unscored';
  ai_explanation: string | null;
  ai_remediation: string | null;
  ai_model: string | null;
  ai_error: string | null;
  created_at: string;
  asset_name: string;
  asset_url: string;
}

interface VulnCheck {
  id: number;
  snapshot_id: number;
  check_type: string;
  passed: number;
  details: string;
}

interface SnapshotDetail {
  id: number;
  asset_id: number;
  captured_at: string;
  http_status: number | null;
  fetch_error: string | null;
  response_headers: Record<string, string>;
  screenshot_available: boolean;
  html_available: boolean;
  phash: string | null;
  html_sha256: string | null;
  diff_result: {
    visual_distance: number | null;
    visual_changed: number;
    text_changed: number;
    text_diff_summary: string | null;
  } | null;
  vuln_results: VulnCheck[];
}

interface AuditLog {
  seq: number;
  created_at: string;
  actor: string;
  action: string;
  entity_type: string | null;
  entity_id: number | null;
  details: any;
  prev_hash: string;
  entry_hash: string;
}

export default function App() {
  // Navigation & User Session
  const [screen, setScreen] = useState<'login' | 'dashboard' | 'asset-detail' | 'audit-log' | 'requests' | 'users' | 'intelligence'>('login');
  const [user, setUser] = useState<User | null>(null);
  const [authLoading, setAuthLoading] = useState(true);

  // Auth screen mode (login vs register) and registration state
  const [authMode, setAuthMode] = useState<'login' | 'register'>('login');
  const [registerMsg, setRegisterMsg] = useState('');

  // Notifications
  const [notif, setNotif] = useState<{ pendingRequests?: number; highRiskAlerts?: number }>({});
  const [toast, setToast] = useState('');
  const prevHighRiskRef = useRef<number | null>(null);

  // Security intelligence
  const [intel, setIntel] = useState<any>(null);
  const [briefing, setBriefing] = useState<any>(null);
  const [briefingLoading, setBriefingLoading] = useState(false);
  const [briefingMsg, setBriefingMsg] = useState('');

  // Requests + Users (multi-tenant) state
  const [myRequests, setMyRequests] = useState<any[]>([]);
  const [adminRequests, setAdminRequests] = useState<any[]>([]);
  const [users, setUsers] = useState<any[]>([]);
  const [newRequest, setNewRequest] = useState({ name: '', url: '', note: '', interval: 180 });
  const [requestMsg, setRequestMsg] = useState('');
  const [assetAssignments, setAssetAssignments] = useState<any[]>([]);
  const [assignableUsers, setAssignableUsers] = useState<any[]>([]);
  const [assignUserId, setAssignUserId] = useState<string>('');

  // Connected-site discovery state
  const [discoverOpen, setDiscoverOpen] = useState(false);
  const [discoverForAssetId, setDiscoverForAssetId] = useState<number | null>(null);
  const [discoverForName, setDiscoverForName] = useState('');
  const [discoverLoading, setDiscoverLoading] = useState(false);
  const [discoverSuggestions, setDiscoverSuggestions] = useState<Array<{ host: string; url: string }>>([]);
  const [discoverSelected, setDiscoverSelected] = useState<Record<string, boolean>>({});
  const [expandedParents, setExpandedParents] = useState<Record<number, boolean>>({});

  // Dashboard state
  const [assets, setAssets] = useState<Asset[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [alertSeverityFilter, setAlertSeverityFilter] = useState<string>('');
  const [alertKindFilter, setAlertKindFilter] = useState<string>('');
  const [isAddAssetOpen, setIsAddAssetOpen] = useState(false);
  const [newAsset, setNewAsset] = useState({ name: '', url: '', interval: 180 });
  const [addAssetError, setAddAssetError] = useState('');
  const [addAssetLoading, setAddAssetLoading] = useState(false);

  // Asset Detail state
  const [selectedAssetId, setSelectedAssetId] = useState<number | null>(null);
  const [selectedAsset, setSelectedAsset] = useState<Asset | null>(null);
  const [snapshots, setSnapshots] = useState<any[]>([]);
  const [selectedSnapshotId, setSelectedSnapshotId] = useState<number | null>(null);
  const [snapshotDetail, setSnapshotDetail] = useState<SnapshotDetail | null>(null);
  const [snapshotLoading, setSnapshotLoading] = useState(false);

  // Audit state
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [verifyStatus, setVerifyStatus] = useState<{ checked: boolean; valid: boolean; badSeq?: number } | null>(null);
  const [verifying, setVerifying] = useState(false);


  // Shared error/loading state
  const [errorMsg, setErrorMsg] = useState('');

  // Poll notification counts globally while logged in. For viewers, raise a
  // toast when the number of high-risk alerts on their sites increases.
  useEffect(() => {
    if (!user) return;
    let cancelled = false;
    prevHighRiskRef.current = null; // reset baseline per user; first load sets it silently
    const load = () => {
      fetch('/api/notifications')
        .then((r) => r.json())
        .then((b) => {
          if (cancelled) return;
          const data = b.data || {};
          setNotif(data);
          if (user.role !== 'admin' && typeof data.highRiskAlerts === 'number') {
            const prev = prevHighRiskRef.current;
            if (prev !== null && data.highRiskAlerts > prev) {
              setToast('A high-risk change was detected on one of your monitored sites.');
              setTimeout(() => setToast(''), 9000);
            }
            prevHighRiskRef.current = data.highRiskAlerts;
          }
        })
        .catch(() => {});
    };
    load();
    const iv = setInterval(load, 20000);
    return () => { cancelled = true; clearInterval(iv); };
  }, [user]);

  // Check login on load
  useEffect(() => {
    fetch('/api/auth/me')
      .then((res) => {
        if (res.ok) return res.json();
        throw new Error('Not authenticated');
      })
      .then((body) => {
        setUser(body.data);
        setScreen('dashboard');
      })
      .catch(() => {
        setUser(null);
        setScreen('login');
      })
      .finally(() => setAuthLoading(false));
  }, []);

  // Fetch Dashboard data (assets + alerts)
  const fetchDashboardData = () => {
    fetch('/api/assets')
      .then((res) => res.json())
      .then((body) => setAssets(body.data || []))
      .catch((err) => console.error('Failed to fetch assets:', err));

    let alertUrl = `/api/alerts?limit=50`;
    if (alertSeverityFilter) alertUrl += `&severity=${alertSeverityFilter}`;
    if (alertKindFilter) alertUrl += `&kind=${alertKindFilter}`;

    fetch(alertUrl)
      .then((res) => res.json())
      .then((body) => setAlerts(body.data || []))
      .catch((err) => console.error('Failed to fetch alerts:', err));
  };

  // Auto-polling alerts every 15s when logged in and on Dashboard
  useEffect(() => {
    if (!user || screen !== 'dashboard') return;
    fetchDashboardData();
    const interval = setInterval(fetchDashboardData, 15000);
    return () => clearInterval(interval);
  }, [user, screen, alertSeverityFilter, alertKindFilter]);

  // Fetch Asset details
  useEffect(() => {
    if (screen !== 'asset-detail' || selectedAssetId === null) return;

    // Load active asset metadata
    const assetMeta = assets.find(a => a.id === selectedAssetId);
    if (assetMeta) {
      setSelectedAsset(assetMeta);
    }

    // Fetch snapshot history
    fetch(`/api/assets/${selectedAssetId}/snapshots`)
      .then((res) => res.json())
      .then((body) => {
        const snaps = body.data || [];
        setSnapshots(snaps);
        if (snaps.length > 0) {
          setSelectedSnapshotId(snaps[0].id);
        } else {
          setSnapshotDetail(null);
          setSelectedSnapshotId(null);
        }
      })
      .catch((err) => console.error('Failed to load snapshots:', err));
  }, [screen, selectedAssetId, assets]);

  // Fetch individual snapshot details when selectedSnapshotId changes
  useEffect(() => {
    if (selectedSnapshotId === null) return;
    setSnapshotLoading(true);
    fetch(`/api/snapshots/${selectedSnapshotId}`)
      .then((res) => res.json())
      .then((body) => {
        setSnapshotDetail(body.data);
      })
      .catch((err) => console.error('Failed to load snapshot details:', err))
      .finally(() => setSnapshotLoading(false));
  }, [selectedSnapshotId]);

  // Fetch Audit Logs when entering screen
  useEffect(() => {
    if (screen !== 'audit-log') return;
    setVerifyStatus(null);
    fetch('/api/audit')
      .then((res) => res.json())
      .then((body) => setAuditLogs(body.data || []))
      .catch((err) => console.error('Failed to load audit logs:', err));
  }, [screen]);

  // Handle Login
  const handleLogin = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setErrorMsg('');
    const formData = new FormData(e.currentTarget);
    const username = formData.get('username') as string;
    const password = formData.get('password') as string;

    fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    })
      .then(async (res) => {
        const body = await res.json();
        if (res.ok) return body;
        throw new Error(body.error?.message || 'Login failed');
      })
      .then((body) => {
        setUser(body.data);
        setScreen('dashboard');
      })
      .catch((err) => setErrorMsg(err.message));
  };

  // Handle Logout
  const handleLogout = () => {
    fetch('/api/auth/logout', { method: 'POST' })
      .finally(() => {
        setUser(null);
        setScreen('login');
      });
  };

  // Shared discovery trigger: opens the modal and loads connected-site
  // suggestions for a just-created asset. Used by both direct admin-add and
  // request approval.
  const startDiscovery = (assetId: number, name: string) => {
    setDiscoverForAssetId(assetId);
    setDiscoverForName(name);
    setDiscoverSuggestions([]);
    setDiscoverSelected({});
    setDiscoverOpen(true);
    setDiscoverLoading(true);
    fetch(`/api/assets/${assetId}/discover`)
      .then((r) => r.json())
      .then((b) => setDiscoverSuggestions(b.data?.suggestions || []))
      .catch(() => {})
      .finally(() => setDiscoverLoading(false));
  };

  // Add Asset Handler
  const handleAddAsset = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setAddAssetError('');
    setAddAssetLoading(true);

    fetch('/api/assets', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: newAsset.name,
        url: newAsset.url,
        interval_seconds: newAsset.interval,
      }),
    })
      .then(async (res) => {
        const body = await res.json();
        if (res.ok) return body;
        throw new Error(body.error?.message || 'Failed to add asset');
      })
      .then((body) => {
        setIsAddAssetOpen(false);
        setNewAsset({ name: '', url: '', interval: 180 });
        fetchDashboardData();
        // Kick off connected-site discovery for the newly created asset.
        const created = body.data;
        if (created?.id) {
          startDiscovery(created.id, created.name);
        }
      })
      .catch((err) => setAddAssetError(err.message))
      .finally(() => setAddAssetLoading(false));
  };

  const addSelectedChildren = () => {
    const urls = discoverSuggestions.filter((s) => discoverSelected[s.url]).map((s) => s.url);
    if (!discoverForAssetId || urls.length === 0) {
      setDiscoverOpen(false);
      return;
    }
    fetch(`/api/assets/${discoverForAssetId}/children`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ urls }),
    })
      .then((r) => r.json())
      .then((b) => {
        setDiscoverOpen(false);
        fetchDashboardData();
        const addedCount = b.data?.added?.length || 0;
        const skipped = b.data?.skipped || [];
        if (skipped.length > 0) {
          const reasons = Array.from(new Set(skipped.map((s: any) => s.reason))).join('; ');
          alert(`Added ${addedCount} site(s). ${skipped.length} skipped: ${reasons}`);
        }
      })
      .catch(() => setDiscoverOpen(false));
  };

  // Toggle Asset Active/Inactive (Admin Only)
  const handleToggleAsset = (activeState: boolean) => {
    if (!selectedAssetId) return;
    fetch(`/api/assets/${selectedAssetId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ is_active: activeState ? 1 : 0 }),
    })
      .then((res) => res.json())
      .then((body) => {
        if (body.data) {
          setSelectedAsset(body.data);
          // Refresh asset list in background
          fetch('/api/assets')
            .then(res => res.json())
            .then(b => setAssets(b.data || []));
        }
      })
      .catch((err) => console.error('Failed to toggle asset state:', err));
  };

  // Delete Asset Soft
  const handleDeleteAsset = () => {
    if (!selectedAssetId) return;
    if (!confirm('Are you sure you want to delete this asset? Its history will survive but it will stop monitoring.')) return;

    fetch(`/api/assets/${selectedAssetId}`, {
      method: 'DELETE',
    })
      .then((res) => {
        if (res.ok) {
          setScreen('dashboard');
          fetchDashboardData();
        }
      })
      .catch((err) => console.error('Failed to delete asset:', err));
  };

  // Verify Audit Chain Handler
  const handleVerifyChain = () => {
    setVerifying(true);
    fetch('/api/audit/verify')
      .then((res) => res.json())
      .then((body) => {
        const data = body.data;
        if (data.valid) {
          setVerifyStatus({ checked: true, valid: true });
        } else {
          setVerifyStatus({ checked: true, valid: false, badSeq: data.first_bad_seq });
        }
      })
      .catch((err) => {
        console.error('Verify error:', err);
        setVerifyStatus({ checked: true, valid: false });
      })
      .finally(() => setVerifying(false));
  };

  // Load intelligence data when entering the screen
  useEffect(() => {
    if (!user || screen !== 'intelligence') return;
    setIntel(null);
    fetch('/api/intelligence')
      .then((r) => r.json())
      .then((b) => setIntel(b.data || null))
      .catch(() => {});
  }, [screen, user]);

  const handleGenerateBriefing = () => {
    setBriefingLoading(true);
    setBriefingMsg('');
    setBriefing(null);
    fetch('/api/intelligence/briefing', { method: 'POST' })
      .then((r) => r.json())
      .then((b) => {
        const d = b.data || {};
        if (d.available && d.briefing) setBriefing(d.briefing);
        else setBriefingMsg(d.message || 'AI briefing is not available right now.');
      })
      .catch(() => setBriefingMsg('AI briefing is not available right now.'))
      .finally(() => setBriefingLoading(false));
  };

  // Load requests/users data when entering those screens
  useEffect(() => {
    if (!user) return;
    if (screen === 'requests') {
      fetch('/api/requests/mine')
        .then((r) => r.json())
        .then((b) => setMyRequests(b.data || []))
        .catch(() => {});
      if (user.role === 'admin') {
        fetch('/api/requests?status=pending')
          .then((r) => r.json())
          .then((b) => setAdminRequests(b.data || []))
          .catch(() => {});
      }
    }
    if (screen === 'users' && user.role === 'admin') {
      fetch('/api/users')
        .then((r) => r.json())
        .then((b) => setUsers(b.data || []))
        .catch(() => {});
    }
  }, [screen, user]);

  // Load per-asset assignments (admin, on asset detail)
  const reloadAssignments = (assetId: number) => {
    fetch(`/api/assets/${assetId}/assignments`).then((r) => r.json()).then((b) => setAssetAssignments(b.data || [])).catch(() => {});
  };
  useEffect(() => {
    if (screen !== 'asset-detail' || !user || user.role !== 'admin' || selectedAssetId === null) return;
    reloadAssignments(selectedAssetId);
    fetch('/api/users').then((r) => r.json()).then((b) => setAssignableUsers((b.data || []).filter((u: any) => u.role !== 'admin' && u.status === 'active'))).catch(() => {});
  }, [screen, selectedAssetId, user]);

  const assignViewer = () => {
    if (!selectedAssetId || !assignUserId) return;
    fetch(`/api/assets/${selectedAssetId}/assignments`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user_id: parseInt(assignUserId, 10) }),
    })
      .then(() => { setAssignUserId(''); reloadAssignments(selectedAssetId); })
      .catch((err) => console.error('Assign error:', err));
  };
  const unassignViewer = (userId: number) => {
    if (!selectedAssetId) return;
    fetch(`/api/assets/${selectedAssetId}/assignments/${userId}`, { method: 'DELETE' })
      .then(() => reloadAssignments(selectedAssetId))
      .catch((err) => console.error('Unassign error:', err));
  };

  // Registration (public)
  const handleRegister = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setErrorMsg('');
    setRegisterMsg('');
    const form = new FormData(e.currentTarget);
    fetch('/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: form.get('username'), password: form.get('password') }),
    })
      .then(async (res) => {
        const body = await res.json();
        if (res.ok) return body;
        throw new Error(body.error?.message || 'Registration failed');
      })
      .then((body) => setRegisterMsg(body.data?.message || 'Registration received. Awaiting admin approval.'))
      .catch((err) => setErrorMsg(err.message));
  };

  const reloadRequests = () => {
    fetch('/api/requests/mine').then((r) => r.json()).then((b) => setMyRequests(b.data || [])).catch(() => {});
    if (user?.role === 'admin') {
      fetch('/api/requests?status=pending').then((r) => r.json()).then((b) => setAdminRequests(b.data || [])).catch(() => {});
    }
  };

  const handleSubmitRequest = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setRequestMsg('');
    fetch('/api/requests', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: newRequest.name,
        url: newRequest.url,
        note: newRequest.note,
        interval_seconds: newRequest.interval,
      }),
    })
      .then(async (res) => {
        const body = await res.json();
        if (res.ok) return body;
        throw new Error(body.error?.message || 'Failed to submit request');
      })
      .then(() => {
        setNewRequest({ name: '', url: '', note: '', interval: 180 });
        setRequestMsg('Request submitted. An administrator will review it.');
        reloadRequests();
      })
      .catch((err) => setRequestMsg(err.message));
  };

  const resolveRequest = (id: number, action: 'approve' | 'reject') => {
    const reqName = adminRequests.find((r) => r.id === id)?.name || 'the approved site';
    fetch(`/api/requests/${id}/${action}`, { method: 'POST' })
      .then(async (res) => {
        const body = await res.json();
        if (!res.ok) throw new Error(body.error?.message || 'Action failed');
        return body;
      })
      .then((body) => {
        reloadRequests();
        // On approval the asset now exists — run connected-site discovery just
        // like a direct admin-add, since the admin is the one accepting it.
        if (action === 'approve' && body.data?.asset_id) {
          fetchDashboardData();
          startDiscovery(body.data.asset_id, reqName);
        }
      })
      .catch((err) => alert(err.message));
  };

  const setUserStatus = (id: number, status: 'active' | 'disabled') => {
    fetch(`/api/users/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status }),
    })
      .then((res) => res.json())
      .then(() => fetch('/api/users').then((r) => r.json()).then((b) => setUsers(b.data || [])))
      .catch((err) => console.error('User status error:', err));
  };

  if (authLoading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh' }}>
        <div className="loader"></div>
      </div>
    );
  }

  return (
    <div className="app-container">
      {/* Navigation bar, visible only when logged in */}
      {user && (
        <header className="navbar">
          <div className="nav-logo" onClick={() => setScreen('dashboard')} style={{ cursor: 'pointer' }}>
            <span>🛡️</span> KavachAI
          </div>
          <nav className="nav-links">
            <button className={`nav-link ${screen === 'dashboard' || screen === 'asset-detail' ? 'active' : ''}`} onClick={() => setScreen('dashboard')}>
              Dashboard
              {user.role !== 'admin' && (notif.highRiskAlerts || 0) > 0 && (
                <span className="nav-badge">{notif.highRiskAlerts}</span>
              )}
            </button>
            <button className={`nav-link ${screen === 'intelligence' ? 'active' : ''}`} onClick={() => setScreen('intelligence')}>
              Intelligence
            </button>
            <button className={`nav-link ${screen === 'requests' ? 'active' : ''}`} onClick={() => setScreen('requests')}>
              Requests
              {user.role === 'admin' && (notif.pendingRequests || 0) > 0 && (
                <span className="nav-badge">{notif.pendingRequests}</span>
              )}
            </button>
            {user.role === 'admin' && (
              <button className={`nav-link ${screen === 'users' ? 'active' : ''}`} onClick={() => setScreen('users')}>
                Users
              </button>
            )}
            {user.role === 'admin' && (
              <button className={`nav-link ${screen === 'audit-log' ? 'active' : ''}`} onClick={() => setScreen('audit-log')}>
                Audit Logs
              </button>
            )}
            <div style={{ display: 'flex', alignItems: 'center', gap: '15px', marginLeft: '10px', paddingLeft: '15px', borderLeft: '1px solid var(--border-color)' }}>
              <span style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
                {user.username} <span style={{ opacity: 0.6, fontSize: '11px' }}>({user.role})</span>
              </span>
              <button className="btn btn-secondary" style={{ padding: '6px 12px', fontSize: '12px' }} onClick={handleLogout}>
                Logout
              </button>
            </div>
          </nav>
        </header>
      )}

      {/* Screen Container */}
      <main className="main-content">
        {screen === 'login' && (
          <div className="login-wrapper">
            <div className="login-card glass-card">
              <h1 className="login-title">KavachAI</h1>
              <p className="login-subtitle">Defacement & Vulnerability Monitor</p>

              {errorMsg && (
                <div style={{ background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.3)', color: 'var(--danger-color)', padding: '12px', borderRadius: '8px', marginBottom: '20px', fontSize: '14px' }}>
                  {errorMsg}
                </div>
              )}
              {registerMsg && (
                <div style={{ background: 'rgba(34, 197, 94, 0.1)', border: '1px solid rgba(34, 197, 94, 0.3)', color: 'var(--success-color)', padding: '12px', borderRadius: '8px', marginBottom: '20px', fontSize: '14px' }}>
                  {registerMsg}
                </div>
              )}

              {authMode === 'login' ? (
                <form onSubmit={handleLogin}>
                  <div className="form-group">
                    <label htmlFor="username">Username</label>
                    <input type="text" id="username" name="username" required placeholder="you@example.com" />
                  </div>
                  <div className="form-group">
                    <label htmlFor="password">Password</label>
                    <input type="password" id="password" name="password" required placeholder="••••••••" />
                  </div>
                  <button type="submit" className="btn btn-primary" style={{ width: '100%', marginTop: '10px' }}>
                    Log In Securely
                  </button>
                  <p style={{ textAlign: 'center', marginTop: '16px', fontSize: '13px', color: 'var(--text-secondary)' }}>
                    Need monitoring access?{' '}
                    <a onClick={() => { setAuthMode('register'); setErrorMsg(''); setRegisterMsg(''); }} style={{ color: 'var(--accent-primary)', cursor: 'pointer' }}>
                      Register as a viewer
                    </a>
                  </p>
                </form>
              ) : (
                <form onSubmit={handleRegister}>
                  <div className="form-group">
                    <label htmlFor="reg-username">Email</label>
                    <input type="email" id="reg-username" name="username" required placeholder="you@example.com" />
                  </div>
                  <div className="form-group">
                    <label htmlFor="reg-password">Password</label>
                    <input type="password" id="reg-password" name="password" required minLength={8} placeholder="At least 8 characters" />
                  </div>
                  <button type="submit" className="btn btn-primary" style={{ width: '100%', marginTop: '10px' }}>
                    Request Viewer Account
                  </button>
                  <p style={{ textAlign: 'center', marginTop: '16px', fontSize: '13px', color: 'var(--text-secondary)' }}>
                    New accounts require administrator approval before sign-in.{' '}
                    <a onClick={() => { setAuthMode('login'); setErrorMsg(''); }} style={{ color: 'var(--accent-primary)', cursor: 'pointer' }}>
                      Back to login
                    </a>
                  </p>
                </form>
              )}
            </div>
          </div>
        )}

        {screen === 'requests' && (
          <div>
            <div className="section-header">
              <h1 style={{ fontSize: '28px' }}>Monitoring Requests</h1>
            </div>

            {user?.role === 'admin' && (
              <div className="glass-card" style={{ padding: '24px', marginBottom: '24px' }}>
                <h3 style={{ marginBottom: '16px', fontSize: '18px' }}>Pending Requests</h3>
                {adminRequests.length === 0 ? (
                  <p style={{ color: 'var(--text-muted)' }}>No pending requests.</p>
                ) : (
                  <div className="history-table-container">
                    <table>
                      <thead>
                        <tr><th>Requester</th><th>Name</th><th>URL</th><th>Note</th><th>Interval</th><th>Actions</th></tr>
                      </thead>
                      <tbody>
                        {adminRequests.map((r) => (
                          <tr key={r.id}>
                            <td>{r.requester}</td>
                            <td>{r.name}</td>
                            <td style={{ maxWidth: 240, overflow: 'hidden', textOverflow: 'ellipsis' }}>{r.url}</td>
                            <td>{r.note || '—'}</td>
                            <td>{r.interval_seconds}s</td>
                            <td style={{ display: 'flex', gap: '8px' }}>
                              <button className="btn btn-primary" style={{ padding: '4px 10px', fontSize: '12px' }} onClick={() => resolveRequest(r.id, 'approve')}>Approve</button>
                              <button className="btn btn-danger" style={{ padding: '4px 10px', fontSize: '12px' }} onClick={() => resolveRequest(r.id, 'reject')}>Reject</button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}

            {user?.role !== 'admin' && (
              <div className="glass-card" style={{ padding: '24px', marginBottom: '24px' }}>
                <h3 style={{ marginBottom: '16px', fontSize: '18px' }}>Request a Site to Monitor</h3>
                {requestMsg && (
                  <div style={{ background: 'rgba(99,102,241,0.1)', border: '1px solid var(--border-color)', color: 'var(--text-secondary)', padding: '10px', borderRadius: '6px', marginBottom: '15px', fontSize: '13px' }}>
                    {requestMsg}
                  </div>
                )}
                <form onSubmit={handleSubmitRequest}>
                  <div className="form-group">
                    <label>Display Name</label>
                    <input type="text" required value={newRequest.name} onChange={(e) => setNewRequest({ ...newRequest, name: e.target.value })} placeholder="Acme Landing Page" />
                  </div>
                  <div className="form-group">
                    <label>Target URL</label>
                    <input type="url" required value={newRequest.url} onChange={(e) => setNewRequest({ ...newRequest, url: e.target.value })} placeholder="https://example.com" />
                  </div>
                  <div className="form-group">
                    <label>Note (optional)</label>
                    <input type="text" value={newRequest.note} onChange={(e) => setNewRequest({ ...newRequest, note: e.target.value })} placeholder="Why this site should be monitored" />
                  </div>
                  <div className="form-group">
                    <label>Capture Interval (seconds)</label>
                    <input type="number" min={120} max={300} required value={newRequest.interval} onChange={(e) => setNewRequest({ ...newRequest, interval: parseInt(e.target.value, 10) })} />
                  </div>
                  <button type="submit" className="btn btn-primary">Submit Request</button>
                </form>
              </div>
            )}

            <div className="glass-card" style={{ padding: '24px' }}>
              <h3 style={{ marginBottom: '16px', fontSize: '18px' }}>My Requests</h3>
              {myRequests.length === 0 ? (
                <p style={{ color: 'var(--text-muted)' }}>You have not submitted any requests.</p>
              ) : (
                <div className="history-table-container">
                  <table>
                    <thead>
                      <tr><th>Name</th><th>URL</th><th>Status</th><th>Requested</th></tr>
                    </thead>
                    <tbody>
                      {myRequests.map((r) => (
                        <tr key={r.id}>
                          <td>{r.name}</td>
                          <td style={{ maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis' }}>{r.url}</td>
                          <td>
                            <span className={`badge ${r.status === 'approved' ? 'badge-success' : r.status === 'rejected' ? 'badge-high' : 'badge-unscored'}`}>
                              {r.status}
                            </span>
                          </td>
                          <td>{new Date(r.created_at).toLocaleString()}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}

        {screen === 'users' && user?.role === 'admin' && (
          <div>
            <div className="section-header">
              <h1 style={{ fontSize: '28px' }}>User Accounts</h1>
            </div>
            <div className="glass-card" style={{ padding: '24px' }}>
              {users.length === 0 ? (
                <p style={{ color: 'var(--text-muted)' }}>No users.</p>
              ) : (
                <div className="history-table-container">
                  <table>
                    <thead>
                      <tr><th>Username</th><th>Role</th><th>Status</th><th>Created</th><th>Actions</th></tr>
                    </thead>
                    <tbody>
                      {users.map((u) => (
                        <tr key={u.id}>
                          <td>{u.username}</td>
                          <td>{u.role}</td>
                          <td>
                            <span className={`badge ${u.status === 'active' ? 'badge-success' : u.status === 'pending' ? 'badge-unscored' : 'badge-high'}`}>
                              {u.status}
                            </span>
                          </td>
                          <td>{new Date(u.created_at).toLocaleString()}</td>
                          <td style={{ display: 'flex', gap: '8px' }}>
                            {u.role !== 'admin' && u.status !== 'active' && (
                              <button className="btn btn-primary" style={{ padding: '4px 10px', fontSize: '12px' }} onClick={() => setUserStatus(u.id, 'active')}>Approve</button>
                            )}
                            {u.role !== 'admin' && u.status === 'active' && (
                              <button className="btn btn-danger" style={{ padding: '4px 10px', fontSize: '12px' }} onClick={() => setUserStatus(u.id, 'disabled')}>Disable</button>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}

        {screen === 'intelligence' && (
          <div>
            <div className="section-header">
              <h1 style={{ fontSize: '28px' }}>Security Intelligence</h1>
              <button className="btn btn-primary" onClick={handleGenerateBriefing} disabled={briefingLoading}>
                {briefingLoading ? 'Generating…' : 'Generate AI Briefing'}
              </button>
            </div>

            {intel && (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginBottom: 24 }}>
                {[
                  { label: 'Assets Monitored', value: String(intel.summary.count), danger: false },
                  { label: 'Avg Posture Score', value: `${intel.summary.avgScore}/100`, danger: intel.summary.avgScore < 50 },
                  { label: 'High-Risk Assets', value: String(intel.summary.highRisk), danger: intel.summary.highRisk > 0 },
                  { label: 'Avg Compliance', value: `${intel.summary.avgCompliance}%`, danger: intel.summary.avgCompliance < 50 },
                ].map((c) => (
                  <div key={c.label} className="glass-card" style={{ padding: 18 }}>
                    <div style={{ fontSize: 11, textTransform: 'uppercase', color: 'var(--text-muted)', letterSpacing: '0.05em' }}>{c.label}</div>
                    <div style={{ fontSize: 26, fontWeight: 700, marginTop: 6, color: c.danger ? 'var(--danger-color)' : 'var(--text-primary)' }}>{c.value}</div>
                  </div>
                ))}
              </div>
            )}

            {(briefing || briefingMsg || briefingLoading) && (
              <div className="glass-card" style={{ padding: 24, marginBottom: 24 }}>
                <h3 style={{ marginBottom: 12, fontSize: 18 }}>AI Security Briefing</h3>
                {briefingLoading ? (
                  <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                    <div className="loader" />
                    <span style={{ color: 'var(--text-muted)', fontSize: 13 }}>Analyzing your portfolio…</span>
                  </div>
                ) : briefing ? (
                  <div>
                    <span className={`badge ${briefing.postureRating === 'strong' ? 'badge-success' : briefing.postureRating === 'weak' ? 'badge-high' : 'badge-medium'}`}>{briefing.postureRating} posture</span>
                    <p style={{ marginTop: 12, color: 'var(--text-primary)', lineHeight: 1.6 }}>{briefing.overallSummary}</p>
                    {briefing.topRisks?.length > 0 && (
                      <div style={{ marginTop: 16 }}>
                        <strong style={{ fontSize: 13 }}>Top Risks</strong>
                        <ul style={{ marginTop: 6, paddingLeft: 18, color: 'var(--text-secondary)', fontSize: 14 }}>
                          {briefing.topRisks.map((r: string, i: number) => <li key={i} style={{ marginBottom: 4 }}>{r}</li>)}
                        </ul>
                      </div>
                    )}
                    {briefing.emergingThreats?.length > 0 && (
                      <div style={{ marginTop: 16 }}>
                        <strong style={{ fontSize: 13, color: 'var(--warning-color)' }}>Emerging Threats</strong>
                        <ul style={{ marginTop: 6, paddingLeft: 18, color: 'var(--text-secondary)', fontSize: 14 }}>
                          {briefing.emergingThreats.map((r: string, i: number) => <li key={i} style={{ marginBottom: 4 }}>{r}</li>)}
                        </ul>
                      </div>
                    )}
                    {briefing.recommendedActions?.length > 0 && (
                      <div style={{ marginTop: 16 }}>
                        <strong style={{ fontSize: 13, color: 'var(--accent-primary)' }}>Recommended Actions</strong>
                        <ul style={{ marginTop: 6, paddingLeft: 18, color: 'var(--text-secondary)', fontSize: 14 }}>
                          {briefing.recommendedActions.map((r: string, i: number) => <li key={i} style={{ marginBottom: 4 }}>{r}</li>)}
                        </ul>
                      </div>
                    )}
                    <div style={{ marginTop: 14, fontSize: 12, color: 'var(--text-muted)' }}>Generated by KavachAI</div>
                  </div>
                ) : (
                  <p style={{ color: 'var(--text-secondary)', fontSize: 14 }}>{briefingMsg}</p>
                )}
              </div>
            )}

            <div className="glass-card" style={{ padding: 24 }}>
              <h3 style={{ marginBottom: 16, fontSize: 18 }}>Risk Ranking — most urgent first</h3>
              {!intel ? (
                <div className="loader" />
              ) : intel.assets.length === 0 ? (
                <p style={{ color: 'var(--text-muted)' }}>No assets to analyze yet.</p>
              ) : (
                <div className="history-table-container">
                  <table>
                    <thead>
                      <tr><th>#</th><th>Asset</th><th>Posture</th><th>Compliance</th><th>Top Signal</th></tr>
                    </thead>
                    <tbody>
                      {intel.assets.map((a: any, i: number) => (
                        <tr key={a.id} style={{ cursor: 'pointer' }} onClick={() => { setSelectedAssetId(a.id); setScreen('asset-detail'); }}>
                          <td>{i + 1}</td>
                          <td>
                            <div style={{ fontWeight: 600 }}>{a.name}</div>
                            <div style={{ fontSize: 11, color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 240 }}>{a.url}</div>
                          </td>
                          <td>
                            <span className={`badge ${a.score >= 70 ? 'badge-success' : a.score >= 50 ? 'badge-medium' : 'badge-high'}`}>{a.grade}</span>
                            <span style={{ marginLeft: 8, fontSize: 13 }}>{a.score}/100</span>
                          </td>
                          <td>{a.compliance.passed}/{a.compliance.total} ({a.compliance.pct}%)</td>
                          <td style={{ fontSize: 12, color: a.signals.length ? 'var(--warning-color)' : 'var(--text-muted)', maxWidth: 260 }}>{a.signals.length ? a.signals[0] : '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}

        {screen === 'dashboard' && (
          <div className="dashboard-grid">
            {/* Left Column: Alert Feed */}
            <div>
              <div className="section-header">
                <h2 className="section-title">Alert Feed</h2>
                <div style={{ display: 'flex', gap: '10px' }}>
                  <select
                    style={{ width: 'auto', padding: '6px 10px', fontSize: '12px' }}
                    value={alertSeverityFilter}
                    onChange={(e) => setAlertSeverityFilter(e.target.value)}
                  >
                    <option value="">All Severities</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                    <option value="unscored">Unscored</option>
                  </select>
                  <select
                    style={{ width: 'auto', padding: '6px 10px', fontSize: '12px' }}
                    value={alertKindFilter}
                    onChange={(e) => setAlertKindFilter(e.target.value)}
                  >
                    <option value="">All Kinds</option>
                    <option value="change">Defacement/Change</option>
                    <option value="vuln">Vulnerability</option>
                    <option value="availability">Availability</option>
                  </select>
                </div>
              </div>

              {alerts.length === 0 ? (
                <div className="glass-card empty-state">
                  <p>No alerts recorded yet. Monitored assets are currently passing check thresholds.</p>
                </div>
              ) : (
                <div className="alert-feed">
                  {alerts.map((alert) => (
                    <div key={alert.id} className={`alert-item glass-card severity-${alert.severity}`}>
                      <div className="alert-top">
                        <div>
                          <span className={`badge badge-${alert.severity}`} style={{ marginRight: '10px' }}>
                            {alert.severity}
                          </span>
                          <span className="badge badge-success" style={{ background: 'rgba(255,255,255,0.05)', color: 'var(--text-secondary)' }}>
                            {alert.kind}
                          </span>
                          <h3 className="alert-title-text" style={{ marginTop: '8px' }}>{alert.title}</h3>
                        </div>
                        <span className="alert-time">{new Date(alert.created_at).toLocaleTimeString()}</span>
                      </div>
                      
                      <div className="alert-body">
                        <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '8px' }}>
                          Asset: <strong>{alert.asset_name}</strong> (<a href={alert.asset_url} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--text-secondary)' }}>{alert.asset_url}</a>)
                        </div>
                        {alert.severity === 'unscored' ? (
                          <p style={{ marginTop: '8px', color: 'var(--text-secondary)', fontSize: '13px' }}>
                            ⚠️ AI risk scoring is not available for this alert right now. Please review the detected change and any failed checks manually.
                          </p>
                        ) : (
                          alert.ai_explanation && (
                            <p style={{ marginTop: '8px', color: 'var(--text-primary)' }}>{alert.ai_explanation}</p>
                          )
                        )}
                      </div>

                      {alert.severity !== 'unscored' && alert.ai_remediation && (
                        <div className="alert-remediation">
                          <strong>Remediation Suggestion:</strong> {alert.ai_remediation}
                        </div>
                      )}

                      <div className="alert-meta">
                        <span>Analyzed by KavachAI</span>
                        <span>•</span>
                        <span style={{ cursor: 'pointer', textDecoration: 'underline' }} onClick={() => {
                          setSelectedAssetId(alert.asset_id);
                          setScreen('asset-detail');
                        }}>
                          View History & Snapshots
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Right Column: Asset List */}
            <div>
              <div className="section-header">
                <h2 className="section-title">Monitored Assets</h2>
                {user?.role === 'admin' && (
                  <button className="btn btn-primary" style={{ padding: '6px 12px', fontSize: '12px' }} onClick={() => setIsAddAssetOpen(true)}>
                    + Add
                  </button>
                )}
              </div>

              <div className="asset-list">
                {assets.filter((a) => !a.parent_asset_id || !assets.some((p) => p.id === a.parent_asset_id)).map((asset) => {
                  const children = assets.filter((c) => c.parent_asset_id === asset.id);
                  const expanded = !!expandedParents[asset.id];
                  return (
                    <div key={asset.id} className="asset-card glass-card" style={{ cursor: 'pointer' }} onClick={() => {
                      setSelectedAssetId(asset.id);
                      setScreen('asset-detail');
                    }}>
                      <div className="asset-info">
                        <div>
                          <div className="asset-name">{asset.name}</div>
                          <span className="asset-url">{asset.url}</span>
                        </div>
                        <span className={`badge ${asset.is_active ? 'badge-success' : 'badge-unscored'}`}>
                          {asset.is_active ? 'Active' : 'Paused'}
                        </span>
                      </div>

                      <div className="asset-stats">
                        <div>
                          {asset.vuln_state.length > 0 ? (
                            <span style={{ color: 'var(--danger-color)', fontWeight: 'bold' }}>
                              ⚠️ {asset.vuln_state.length} vulnerability findings
                            </span>
                          ) : (
                            <span style={{ color: 'var(--success-color)' }}>✓ Clean</span>
                          )}
                        </div>
                        <div style={{ color: 'var(--text-muted)', fontSize: '11px' }}>
                          Every {asset.interval_seconds}s
                        </div>
                      </div>

                      {children.length > 0 && (
                        <div style={{ marginTop: '12px', borderTop: '1px solid var(--border-color)', paddingTop: '10px' }}>
                          <div
                            onClick={(e) => { e.stopPropagation(); setExpandedParents((p) => ({ ...p, [asset.id]: !expanded })); }}
                            style={{ fontSize: '12px', color: 'var(--text-secondary)', cursor: 'pointer' }}
                          >
                            {expanded ? '▾' : '▸'} {children.length} connected site{children.length > 1 ? 's' : ''}
                          </div>
                          {expanded && (
                            <div style={{ marginTop: '8px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
                              {children.map((child) => (
                                <div
                                  key={child.id}
                                  onClick={(e) => { e.stopPropagation(); setSelectedAssetId(child.id); setScreen('asset-detail'); }}
                                  style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'rgba(0,0,0,0.2)', borderRadius: '6px', padding: '8px 10px' }}
                                >
                                  <span style={{ fontSize: '12px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '70%' }}>{child.name}</span>
                                  {child.vuln_state.length > 0 ? (
                                    <span className="badge badge-high" style={{ fontSize: '10px' }}>{child.vuln_state.length}</span>
                                  ) : (
                                    <span className="badge badge-success" style={{ fontSize: '10px' }}>OK</span>
                                  )}
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        )}

        {screen === 'asset-detail' && selectedAsset && (
          <div>
            {/* Header section */}
            <div className="asset-detail-header">
              <div>
                <button className="btn btn-secondary" style={{ marginBottom: '15px', padding: '6px 12px', fontSize: '12px' }} onClick={() => setScreen('dashboard')}>
                  ← Back to Dashboard
                </button>
                <h1 style={{ fontSize: '28px', display: 'flex', alignItems: 'center', gap: '15px' }}>
                  {selectedAsset.name}
                  <span className={`badge ${selectedAsset.is_active ? 'badge-success' : 'badge-unscored'}`} style={{ fontSize: '12px' }}>
                    {selectedAsset.is_active ? 'Active Monitoring' : 'Paused'}
                  </span>
                </h1>
                <a href={selectedAsset.url} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--text-secondary)', fontSize: '14px', textDecoration: 'none', display: 'inline-block', marginTop: '6px' }}>
                  🔗 {selectedAsset.url}
                </a>
              </div>

              {user?.role === 'admin' && (
                <div style={{ display: 'flex', gap: '10px' }}>
                  <button
                    className={`btn ${selectedAsset.is_active ? 'btn-secondary' : 'btn-primary'}`}
                    style={{ padding: '8px 16px' }}
                    onClick={() => handleToggleAsset(!selectedAsset.is_active)}
                  >
                    {selectedAsset.is_active ? 'Pause Capture' : 'Resume Capture'}
                  </button>
                  <button className="btn btn-danger" style={{ padding: '8px 16px' }} onClick={handleDeleteAsset}>
                    Delete Asset
                  </button>
                </div>
              )}
            </div>

            {/* Assigned viewers (admin only) */}
            {user?.role === 'admin' && (
              <div className="glass-card" style={{ padding: '20px', marginBottom: '20px' }}>
                <h3 style={{ marginBottom: '12px', fontSize: '16px' }}>Viewer Access</h3>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', alignItems: 'center', marginBottom: '12px' }}>
                  {assetAssignments.length === 0 ? (
                    <span style={{ color: 'var(--text-muted)', fontSize: '13px' }}>No viewers assigned yet.</span>
                  ) : (
                    assetAssignments.map((a) => (
                      <span key={a.user_id} className="badge badge-success" style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                        {a.username}
                        <a onClick={() => unassignViewer(a.user_id)} style={{ cursor: 'pointer', color: 'var(--danger-color)', fontWeight: 'bold' }}>×</a>
                      </span>
                    ))
                  )}
                </div>
                <div style={{ display: 'flex', gap: '8px' }}>
                  <select value={assignUserId} onChange={(e) => setAssignUserId(e.target.value)} style={{ width: 'auto', padding: '6px 10px', fontSize: '13px' }}>
                    <option value="">Select a viewer…</option>
                    {assignableUsers
                      .filter((u) => !assetAssignments.some((a) => a.user_id === u.id))
                      .map((u) => (
                        <option key={u.id} value={u.id}>{u.username}</option>
                      ))}
                  </select>
                  <button className="btn btn-primary" style={{ padding: '6px 12px', fontSize: '13px' }} onClick={assignViewer} disabled={!assignUserId}>
                    Grant Access
                  </button>
                </div>
              </div>
            )}

            {/* Split layout: screenshot vs diff details */}
            <div className="asset-detail-grid">
              {/* Left Pane: Screenshot and vuln details */}
              <div className="glass-card" style={{ padding: '24px' }}>
                <h3 style={{ marginBottom: '16px', fontSize: '18px' }}>Visual Snapshot Capture</h3>
                
                <div className="screenshot-view">
                  {snapshotLoading ? (
                    <div className="loader"></div>
                  ) : snapshotDetail?.screenshot_available ? (
                    <img
                      src={`/api/snapshots/${snapshotDetail.id}/screenshot`}
                      alt="Latest page capture viewport"
                      className="screenshot-img"
                    />
                  ) : (
                    <div className="screenshot-placeholder">
                      {snapshotDetail?.fetch_error ? (
                        <p style={{ color: 'var(--danger-color)' }}>⚠️ Pipeline Capture Error: {snapshotDetail.fetch_error}</p>
                      ) : (
                        <p>No screenshot captured for this snapshot baseline</p>
                      )}
                    </div>
                  )}
                </div>

                <h3 style={{ marginTop: '30px', marginBottom: '16px', fontSize: '18px' }}>Security Headers & File Exposure</h3>
                <div className="vuln-list">
                  {snapshotDetail?.vuln_results.map((vuln) => (
                    <div key={vuln.id} className="vuln-check-item">
                      <span className="vuln-check-name">{vuln.check_type.replace('header_', '').toUpperCase()} check</span>
                      <span className={`badge ${vuln.passed ? 'badge-success' : 'badge-high'}`}>
                        {vuln.passed ? 'Passed' : 'Failed'}
                      </span>
                    </div>
                  )) || <p style={{ color: 'var(--text-muted)' }}>No vulnerability evaluation available for this snapshot.</p>}
                </div>
              </div>

              {/* Right Pane: Diff and properties */}
              <div className="glass-card" style={{ padding: '24px' }}>
                <h3 style={{ marginBottom: '16px', fontSize: '18px' }}>HTML and Perceptual Difference</h3>
                
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '15px', marginBottom: '20px' }}>
                  <div style={{ background: 'rgba(0,0,0,0.2)', padding: '12px', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
                    <div style={{ color: 'var(--text-muted)', fontSize: '11px', textTransform: 'uppercase' }}>Visual dHash Distance</div>
                    <div style={{ fontSize: '20px', fontWeight: 'bold', marginTop: '4px', color: (snapshotDetail?.diff_result?.visual_distance ?? 0) > 10 ? 'var(--warning-color)' : 'var(--success-color)' }}>
                      {snapshotDetail?.diff_result?.visual_distance !== null && snapshotDetail?.diff_result?.visual_distance !== undefined
                        ? `${snapshotDetail.diff_result.visual_distance} / 64`
                        : 'N/A (Baseline)'}
                    </div>
                  </div>
                  <div style={{ background: 'rgba(0,0,0,0.2)', padding: '12px', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
                    <div style={{ color: 'var(--text-muted)', fontSize: '11px', textTransform: 'uppercase' }}>HTML SHA-256 Changed</div>
                    <div style={{ fontSize: '20px', fontWeight: 'bold', marginTop: '4px', color: snapshotDetail?.diff_result?.text_changed ? 'var(--warning-color)' : 'var(--success-color)' }}>
                      {snapshotDetail?.diff_result ? (snapshotDetail.diff_result.text_changed ? 'Yes' : 'No') : 'N/A (Baseline)'}
                    </div>
                  </div>
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                  <strong>HTML Source Diff Summary:</strong>
                  {snapshotDetail?.id && (
                    <a
                      href={`/api/snapshots/${snapshotDetail.id}/html`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="btn btn-secondary"
                      style={{ padding: '4px 10px', fontSize: '11px' }}
                    >
                      View Raw HTML Capture (txt)
                    </a>
                  )}
                </div>

                {snapshotDetail?.diff_result?.text_diff_summary ? (
                  <pre className="diff-viewer">{snapshotDetail.diff_result.text_diff_summary}</pre>
                ) : (
                  <div className="empty-state" style={{ background: '#0d0e15', borderRadius: '8px', border: '1px solid var(--border-color)', height: '200px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    <p style={{ fontSize: '13px' }}>No HTML line differences detected relative to the previous capture.</p>
                  </div>
                )}
              </div>
            </div>

            {/* Bottom Section: Capture History Table */}
            <div className="glass-card" style={{ padding: '24px', marginTop: '30px' }}>
              <h3 style={{ marginBottom: '16px', fontSize: '18px' }}>Capture Snapshots History</h3>
              {snapshots.length === 0 ? (
                <p style={{ color: 'var(--text-muted)' }}>No captures recorded yet for this asset.</p>
              ) : (
                <div className="history-table-container">
                  <table>
                    <thead>
                      <tr>
                        <th>Snapshot ID</th>
                        <th>Captured Time</th>
                        <th>HTTP Status</th>
                        <th>Visual Change</th>
                        <th>Text Change</th>
                        <th>Vulnerability Count</th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {snapshots.map((snap) => {
                        const failedCount = snap.vuln_checks?.filter((c: any) => c.passed === 0).length || 0;
                        return (
                          <tr key={snap.id} style={{ background: selectedSnapshotId === snap.id ? 'rgba(99, 102, 241, 0.08)' : 'transparent' }}>
                            <td>#{snap.id}</td>
                            <td>{new Date(snap.captured_at).toLocaleString()}</td>
                            <td>
                              {snap.http_status ? (
                                <span style={{ color: snap.http_status >= 500 ? 'var(--danger-color)' : 'var(--success-color)' }}>
                                  {snap.http_status}
                                </span>
                              ) : (
                                <span style={{ color: 'var(--danger-color)' }}>Error</span>
                              )}
                            </td>
                            <td>{snap.diff_result?.visual_changed ? '⚠️ Yes' : 'No'}</td>
                            <td>{snap.diff_result?.text_changed ? '⚠️ Yes' : 'No'}</td>
                            <td>
                              {failedCount > 0 ? (
                                <span style={{ color: 'var(--danger-color)', fontWeight: 'bold' }}>{failedCount} failed</span>
                              ) : (
                                <span style={{ color: 'var(--success-color)' }}>All Passed</span>
                              )}
                            </td>
                            <td>
                              <button
                                className="btn btn-secondary"
                                style={{ padding: '4px 10px', fontSize: '12px' }}
                                onClick={() => setSelectedSnapshotId(snap.id)}
                              >
                                Inspect
                              </button>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}

        {screen === 'audit-log' && (
          <div>
            <div className="section-header">
              <h1 style={{ fontSize: '28px' }}>Security Audit Log</h1>
              <button
                className="btn btn-primary"
                style={{ padding: '8px 16px' }}
                onClick={handleVerifyChain}
                disabled={verifying}
              >
                {verifying ? 'Verifying Integrity...' : 'Verify Chain Integrity'}
              </button>
            </div>

            {/* Glowing Validation Banner */}
            {verifyStatus && (
              <div className={`verify-banner ${verifyStatus.valid ? 'valid' : 'invalid'}`}>
                <div>
                  <h3 style={{ fontSize: '18px', fontWeight: 'bold', color: verifyStatus.valid ? 'var(--success-color)' : 'var(--danger-color)' }}>
                    {verifyStatus.valid ? '🔒 SHA-256 Hash Chain Fully Validated' : '🚨 Tamper Detected in Audit Chain'}
                  </h3>
                  <p style={{ fontSize: '14px', marginTop: '6px', color: 'var(--text-secondary)' }}>
                    {verifyStatus.valid
                      ? 'Every block hashes cleanly into the sequence and matches its canonical digest. No rows have been deleted, appended out of order, or retroactively edited.'
                      : `The validation algorithm flagged a hash mismatch or sequence break at block sequence #${verifyStatus.badSeq}. Chain integrity cannot be trusted.`}
                  </p>
                </div>
              </div>
            )}

            {/* Audit log list display */}
            <div className="audit-list">
              {auditLogs.map((log) => (
                <div key={log.seq} className="audit-item glass-card">
                  <div className="audit-meta-row">
                    <span>Block Sequence: <strong>#{log.seq}</strong></span>
                    <span>{new Date(log.created_at).toLocaleString()}</span>
                  </div>
                  <div className="audit-summary">
                    <strong>{log.actor}</strong> triggered <code>{log.action}</code>
                    {log.entity_type && (
                      <span> on entity <code>{log.entity_type}</code> (#{log.entity_id})</span>
                    )}
                  </div>
                  <div style={{ color: 'var(--text-secondary)', marginBottom: '10px', fontSize: '13px' }}>
                    Payload: <code>{JSON.stringify(log.details)}</code>
                  </div>
                  <div className="audit-hash-row">
                    <div><span>Prev:</span> <span style={{ opacity: 0.7 }}>{log.prev_hash}</span></div>
                    <div><span>Hash:</span> <span style={{ color: 'var(--accent-primary)', fontWeight: '500' }}>{log.entry_hash}</span></div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </main>

      {/* High-risk notification toast (viewers) */}
      {toast && (
        <div className="toast">
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            <span style={{ fontWeight: 700, color: 'var(--danger-color)', fontSize: 13 }}>High-risk change detected</span>
            <span style={{ color: 'var(--text-secondary)', fontSize: 13 }}>{toast}</span>
          </div>
          <button
            onClick={() => { setToast(''); setScreen('dashboard'); }}
            className="btn btn-secondary"
            style={{ padding: '4px 10px', fontSize: 12 }}
          >
            View
          </button>
          <button onClick={() => setToast('')} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: 18, lineHeight: 1 }}>×</button>
        </div>
      )}

      {/* Add Asset Modal Panel (Admin Only) */}
      {isAddAssetOpen && (
        <div className="modal-overlay">
          <div className="modal-content glass-card">
            <button className="modal-close" onClick={() => setIsAddAssetOpen(false)}>×</button>
            <h2 style={{ fontSize: '22px', marginBottom: '6px' }}>Register Monitoring Asset</h2>
            <p style={{ color: 'var(--text-secondary)', fontSize: '13px', marginBottom: '20px' }}>
              Add a new web target URL for defacement checks and vulnerability scans.
            </p>

            {addAssetError && (
              <div style={{ background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.3)', color: 'var(--danger-color)', padding: '10px', borderRadius: '6px', marginBottom: '15px', fontSize: '13px' }}>
                {addAssetError}
              </div>
            )}

            <form onSubmit={handleAddAsset}>
              <div className="form-group">
                <label htmlFor="asset-name">Display Name</label>
                <input
                  type="text"
                  id="asset-name"
                  required
                  placeholder="e.g. Acme Corporate Landing"
                  value={newAsset.name}
                  onChange={(e) => setNewAsset({ ...newAsset, name: e.target.value })}
                />
              </div>
              <div className="form-group">
                <label htmlFor="asset-url">Target URL</label>
                <input
                  type="url"
                  id="asset-url"
                  required
                  placeholder="https://example.com"
                  value={newAsset.url}
                  onChange={(e) => setNewAsset({ ...newAsset, url: e.target.value })}
                />
                <p style={{ color: 'var(--text-muted)', fontSize: '11px', marginTop: '4px' }}>
                  Target must resolve to a public IP address. Intranet/Loopback addresses are blocked.
                </p>
              </div>
              <div className="form-group">
                <label htmlFor="asset-interval">Capture Interval (seconds)</label>
                <input
                  type="number"
                  id="asset-interval"
                  required
                  min={120}
                  max={300}
                  value={newAsset.interval}
                  onChange={(e) => setNewAsset({ ...newAsset, interval: parseInt(e.target.value, 10) })}
                />
                <p style={{ color: 'var(--text-muted)', fontSize: '11px', marginTop: '4px' }}>
                  Must be between 120 and 300 seconds.
                </p>
              </div>
              {addAssetLoading && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 16, color: 'var(--text-secondary)', fontSize: 13 }}>
                  <div className="loader" style={{ width: 18, height: 18 }} />
                  <span>Validating the site and checking it's live… this can take a few seconds.</span>
                </div>
              )}
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '12px', marginTop: '20px' }}>
                <button type="button" className="btn btn-secondary" onClick={() => setIsAddAssetOpen(false)} disabled={addAssetLoading}>
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary" disabled={addAssetLoading}>
                  {addAssetLoading ? 'Deploying…' : 'Deploy Scans'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Connected-site discovery modal */}
      {discoverOpen && (
        <div className="modal-overlay">
          <div className="modal-content glass-card">
            <button className="modal-close" onClick={() => setDiscoverOpen(false)}>×</button>
            <h2 style={{ fontSize: '22px', marginBottom: '6px' }}>Connected Sites</h2>
            <p style={{ color: 'var(--text-secondary)', fontSize: '13px', marginBottom: '16px' }}>
              These sites are connected to <strong>{discoverForName}</strong>. Select which to also monitor as sub-sites, grouped under it.
            </p>

            {discoverLoading ? (
              <div style={{ padding: '24px', textAlign: 'center' }}>
                <div className="loader"></div>
                <p style={{ marginTop: 12, color: 'var(--text-muted)', fontSize: 13 }}>Scanning the page for connected sites…</p>
              </div>
            ) : discoverSuggestions.length === 0 ? (
              <p style={{ color: 'var(--text-muted)', fontSize: 13, marginBottom: 16 }}>No additional connected sites were found.</p>
            ) : (
              <>
                <div style={{ display: 'flex', gap: 10, marginBottom: 10 }}>
                  <button className="btn btn-secondary" style={{ padding: '4px 10px', fontSize: 12 }} onClick={() => { const all: Record<string, boolean> = {}; discoverSuggestions.forEach((s) => { all[s.url] = true; }); setDiscoverSelected(all); }}>Select all</button>
                  <button className="btn btn-secondary" style={{ padding: '4px 10px', fontSize: 12 }} onClick={() => setDiscoverSelected({})}>Clear</button>
                  <span style={{ marginLeft: 'auto', fontSize: 12, color: 'var(--text-muted)', alignSelf: 'center' }}>{discoverSuggestions.length} found</span>
                </div>
                <div style={{ maxHeight: 320, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 6, marginBottom: 16 }}>
                  {discoverSuggestions.map((s) => (
                    <label key={s.url} className="select-row">
                      <input type="checkbox" checked={!!discoverSelected[s.url]} onChange={(e) => setDiscoverSelected((p) => ({ ...p, [s.url]: e.target.checked }))} />
                      <span>{s.host}</span>
                    </label>
                  ))}
                </div>
              </>
            )}

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 12 }}>
              <button className="btn btn-secondary" onClick={() => setDiscoverOpen(false)}>Skip</button>
              <button className="btn btn-primary" disabled={discoverLoading || discoverSuggestions.every((s) => !discoverSelected[s.url])} onClick={addSelectedChildren}>Add Selected</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
