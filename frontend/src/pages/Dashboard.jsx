import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import Sidebar from '../components/Sidebar';
import { SeverityBadge, StatusBadge } from '../components/Badges';
import { getKpis, getIncidents } from '../api';

const SEV_COLORS = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e' };

export default function Dashboard() {
  const [kpis, setKpis] = useState(null);
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('all');
  const navigate = useNavigate();

  useEffect(() => {
    Promise.all([getKpis(), getIncidents({ limit: 50 })])
      .then(([k, inc]) => {
        setKpis(k);
        setIncidents(inc);
      })
      .catch((e) => console.error(e))
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="app">
        <Sidebar />
        <div className="main">
          <div className="loading"><div className="spinner"></div> Chargement des données...</div>
        </div>
      </div>
    );
  }

  // Calculs d'affichage
  const feedbackTP = kpis?.feedback_stats?.find((f) => f.label === 'true_positive')?.count || 0;
  const feedbackFP = kpis?.feedback_stats?.find((f) => f.label === 'false_positive')?.count || 0;
  const precision = feedbackTP + feedbackFP > 0 ? Math.round((feedbackTP / (feedbackTP + feedbackFP)) * 100) : '—';

  const maxTactic = Math.max(...(kpis?.by_tactic?.map((t) => t.count) || [1]));
  const totalSev = kpis?.by_severity?.reduce((s, x) => s + Number(x.count), 0) || 1;

  // Construire le conic-gradient du donut
  let acc = 0;
  const donutStops = (kpis?.by_severity || []).map((s) => {
    const start = (acc / totalSev) * 100;
    acc += Number(s.count);
    const end = (acc / totalSev) * 100;
    return `${SEV_COLORS[s.severity?.toLowerCase()] || '#8a97ad'} ${start}% ${end}%`;
  });
  const donutStyle = { background: `conic-gradient(${donutStops.join(', ')})` };

  const filtered = incidents.filter((i) => {
    if (filter === 'all') return true;
    if (filter === 'high') return i.severity?.toLowerCase() === 'high';
    if (filter === 'pending') return i.status === 'pending_approval';
    return true;
  });

  return (
    <div className="app">
      <Sidebar />
      <div className="main">
        <div className="header">
          <div>
            <h1>Tableau de bord</h1>
            <div className="subtitle">Vue d'ensemble des incidents de sécurité</div>
          </div>
          <div className="badge-live"><span className="dot"></span> Pipeline actif</div>
        </div>

        {/* KPI CARDS */}
        <div className="kpi-grid">
          <div className="kpi-card" style={{ '--accent': 'var(--primary)' }}>
            <div className="kpi-label">Incidents totaux</div>
            <div className="kpi-value">{kpis?.total_cases ?? '—'}</div>
            <div className="kpi-sub up">{kpis?.total_alerts ?? 0} alertes traitées</div>
          </div>
          <div className="kpi-card" style={{ '--accent': 'var(--high)' }}>
            <div className="kpi-label">En attente d'approbation</div>
            <div className="kpi-value">{kpis?.pending_approval ?? 0}</div>
            <div className="kpi-sub warn">Action requise</div>
          </div>
          <div className="kpi-card" style={{ '--accent': 'var(--cyan)' }}>
            <div className="kpi-label">Ratio de réduction</div>
            <div className="kpi-value">{kpis?.reduction_ratio ?? '—'}×</div>
            <div className="kpi-sub">Alertes → Incidents</div>
          </div>
          <div className="kpi-card" style={{ '--accent': 'var(--low)' }}>
            <div className="kpi-label">Précision (TP/FP)</div>
            <div className="kpi-value">{precision}{precision !== '—' ? '%' : ''}</div>
            <div className="kpi-sub up">{feedbackTP} TP · {feedbackFP} FP</div>
          </div>
        </div>

        {/* PANELS */}
        <div className="panels">
          <div className="panel">
            <div className="panel-title">Tactiques MITRE ATT&CK <span className="muted">Top {kpis?.by_tactic?.length || 0}</span></div>
            {(kpis?.by_tactic || []).map((t, i) => (
              <div className="bar-row" key={i}>
                <div className="bar-label" title={t.mitre_tactic}>{t.mitre_tactic || 'Inconnu'}</div>
                <div className="bar-track"><div className="bar-fill" style={{ width: `${(t.count / maxTactic) * 100}%` }}></div></div>
                <div className="bar-val">{t.count}</div>
              </div>
            ))}
          </div>
          <div className="panel">
            <div className="panel-title">Répartition par sévérité</div>
            <div className="donut-wrap">
              <div style={{ position: 'relative', width: 130, height: 130 }}>
                <div style={{ ...donutStyle, width: 130, height: 130, borderRadius: '50%' }}></div>
                <div style={{ position: 'absolute', top: 21, left: 21, width: 88, height: 88, borderRadius: '50%', background: 'var(--bg-panel)', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
                  <div style={{ fontSize: 26, fontWeight: 700 }}>{kpis?.total_cases ?? 0}</div>
                  <div style={{ fontSize: 11, color: 'var(--text-dim)' }}>incidents</div>
                </div>
              </div>
              <div className="legend">
                {(kpis?.by_severity || []).map((s, i) => (
                  <div className="legend-item" key={i}>
                    <span className="legend-dot" style={{ background: SEV_COLORS[s.severity?.toLowerCase()] || '#8a97ad' }}></span>
                    {s.severity} · {s.count}
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* TABLE */}
        <div className="table-panel">
          <div className="table-head">
            <h3>Incidents récents</h3>
            <div className="filters">
              <div className={'chip' + (filter === 'all' ? ' active' : '')} onClick={() => setFilter('all')}>Tous</div>
              <div className={'chip' + (filter === 'high' ? ' active' : '')} onClick={() => setFilter('high')}>High</div>
              <div className={'chip' + (filter === 'pending' ? ' active' : '')} onClick={() => setFilter('pending')}>En attente</div>
            </div>
          </div>
          {filtered.length === 0 ? (
            <div className="empty">Aucun incident à afficher.</div>
          ) : (
            <table>
              <thead>
                <tr><th>Incident</th><th>Titre</th><th>Sévérité</th><th>Tactique</th><th>Statut</th><th></th></tr>
              </thead>
              <tbody>
                {filtered.map((inc) => (
                  <tr key={inc.case_id}>
                    <td className="case-id">{inc.case_id}</td>
                    <td>{inc.title || '—'}</td>
                    <td><SeverityBadge severity={inc.severity} /></td>
                    <td className="tactic">{inc.mitre_tactic || '—'}</td>
                    <td><StatusBadge status={inc.status} /></td>
                    <td><button className="btn-analyze" onClick={() => navigate(`/incident/${inc.case_id}`)}>Deep Analysis</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}
