import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import Sidebar from '../components/Sidebar';
import { SeverityBadge, StatusBadge } from '../components/Badges';
import { getIncident, getIncidentAlerts, sendFeedback, approveBlock } from '../api';

export default function DeepAnalysis() {
  const { caseId } = useParams();
  const navigate = useNavigate();
  const [incident, setIncident] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState('overview');
  const [toast, setToast] = useState(null);
  const [acting, setActing] = useState(false);

  useEffect(() => {
    Promise.all([getIncident(caseId), getIncidentAlerts(caseId)])
      .then(([inc, al]) => {
        setIncident(inc);
        setAlerts(al);
      })
      .catch((e) => showToast(e.message, 'error'))
      .finally(() => setLoading(false));
  }, [caseId]);

  function showToast(msg, type = 'success') {
    setToast({ msg, type });
    setTimeout(() => setToast(null), 3500);
  }

  async function handleApprove() {
    setActing(true);
    try {
      await approveBlock(caseId);
      showToast('Blocage approuvé et déclenché ✓', 'success');
      setIncident({ ...incident, status: 'resolved' });
    } catch (e) {
      showToast(e.message || "Échec de l'approbation", 'error');
    } finally {
      setActing(false);
    }
  }

  async function handleReject() {
    setActing(true);
    try {
      await sendFeedback(caseId, 'false_positive');
      showToast('Marqué comme faux positif', 'success');
      setIncident({ ...incident, status: 'closed_fp' });
    } catch (e) {
      showToast(e.message || 'Échec', 'error');
    } finally {
      setActing(false);
    }
  }

  if (loading) {
    return (
      <div className="app">
        <Sidebar />
        <div className="main"><div className="loading"><div className="spinner"></div> Chargement de l'incident...</div></div>
      </div>
    );
  }

  if (!incident) {
    return (
      <div className="app">
        <Sidebar />
        <div className="main"><div className="empty">Incident introuvable.</div></div>
      </div>
    );
  }

  // Données pour l'overview : on prend la première alerte comme représentative
  const a = alerts[0] || {};
  const assets = incident.affected_assets || [];

  return (
    <div className="app">
      <Sidebar />
      <div className="main">
        <button className="back" onClick={() => navigate('/')}>← Retour aux incidents</button>

        <div className="incident-head">
          <div className="incident-title">
            <h1>{incident.title || 'Incident'}</h1>
            <div className="incident-meta">
              <span className="case-id">{incident.case_id}</span>
              <SeverityBadge severity={incident.severity} />
              <StatusBadge status={incident.status} />
            </div>
          </div>
          <div style={{ display: 'flex', gap: 12 }}>
            <button className="btn-reject" onClick={handleReject} disabled={acting}>Rejeter (FP)</button>
            <button className="btn-approve" onClick={handleApprove} disabled={acting}>
              🛡️ {acting ? 'En cours...' : 'Approuver le blocage'}
            </button>
          </div>
        </div>

        <div className="tabs">
          <button className={'tab' + (tab === 'overview' ? ' active' : '')} onClick={() => setTab('overview')}>Incident Overview</button>
          <button className={'tab' + (tab === 'ai' ? ' active' : '')} onClick={() => setTab('ai')}>AI Analysis</button>
        </div>

        {tab === 'overview' && (
          <div className="grid2">
            <div className="panel">
              <div className="panel-subtitle">Informations réseau</div>
              <div className="field"><span className="k">IP Source</span><span className="v hl">{a.src_ip || '—'}</span></div>
              <div className="field"><span className="k">IP Destination</span><span className="v hl">{a.dst_ip || '—'}</span></div>
              <div className="field"><span className="k">Port source</span><span className="v">{a.src_port ?? '—'}</span></div>
              <div className="field"><span className="k">Port destination</span><span className="v">{a.dst_port ?? '—'}</span></div>
              <div className="field"><span className="k">Protocole</span><span className="v">{a.protocol || '—'}</span></div>
            </div>
            <div className="panel">
              <div className="panel-subtitle">Threat Intelligence</div>
              <div className="field"><span className="k">Score de réputation</span><span className="v">{a.abuse_score != null ? `${a.abuse_score}/100` : '— (IP privée)'}</span></div>
              <div className="field"><span className="k">Pays</span><span className="v">{a.country || '— (interne)'}</span></div>
              <div className="field"><span className="k">Score CVSS</span><span className="v">{a.cvss_score != null ? a.cvss_score : 'N/A'}</span></div>
              <div className="field"><span className="k">Score de risque</span><span className="v">{a.risk_score != null ? a.risk_score : '—'}</span></div>
            </div>
            <div className="panel">
              <div className="panel-subtitle">Classification MITRE ATT&CK</div>
              <div className="field"><span className="k">Tactique</span><span className="v hl">{incident.mitre_tactic || '—'}</span></div>
              <div className="field"><span className="k">Technique</span><span className="v hl">{incident.mitre_technique || '—'}</span></div>
            </div>
            <div className="panel">
              <div className="panel-subtitle">Détection</div>
              <div className="field"><span className="k">Agent</span><span className="v">{a.agent_name || '—'}</span></div>
              <div className="field"><span className="k">Règle</span><span className="v">{a.rule_description || '—'}</span></div>
              <div className="field"><span className="k">Niveau</span><span className="v">{a.rule_level != null ? `${a.rule_level}/15` : '—'}</span></div>
            </div>
          </div>
        )}

        {tab === 'ai' && (
          <div className="panel" style={{ marginBottom: 22 }}>
            <div className="ai-block">
              <h4>Cause racine (Root Cause)</h4>
              <p>{incident.title || '—'}</p>
            </div>
            <div className="ai-block">
              <h4>Actifs affectés</h4>
              <div>
                {assets.length > 0 ? assets.map((as, i) => <span className="asset-tag" key={i}>{as}</span>) : <span className="asset-tag">{a.dst_ip || '—'}</span>}
              </div>
            </div>
            <div className="ai-block">
              <h4>Probabilité de faux positif</h4>
              <p>{incident.fp_probability != null ? `${Math.round(incident.fp_probability * 100)}%` : '—'}</p>
            </div>
            <div className="ai-block">
              <h4>Remédiation recommandée</h4>
              <div className="remediation">{incident.remediation || 'Aucune recommandation fournie.'}</div>
            </div>
            <div className="ai-block">
              <h4>Logs bruts (échantillon)</h4>
              <div className="logs-box">{a.raw_alert ? JSON.stringify(a.raw_alert, null, 2).slice(0, 1500) : 'Aucun log disponible.'}</div>
            </div>
          </div>
        )}

        {/* CORRELATION TABLE */}
        <div className="table-panel">
          <div className="table-head">
            <h3>Alertes corrélées</h3>
            <span className="corr-badge">{alerts.length} alerte{alerts.length > 1 ? 's' : ''} → 1 incident</span>
          </div>
          {alerts.length === 0 ? (
            <div className="empty">Aucune alerte corrélée trouvée.</div>
          ) : (
            <table>
              <thead>
                <tr><th>Alert ID</th><th>Horodatage</th><th>Règle</th><th>Src IP</th><th>Dst Port</th><th>Risk</th></tr>
              </thead>
              <tbody>
                {alerts.map((al) => (
                  <tr key={al.alert_id}>
                    <td className="case-id">{(al.alert_id || '').slice(0, 10)}…</td>
                    <td className="mono">{al.timestamp ? new Date(al.timestamp).toLocaleTimeString() : '—'}</td>
                    <td>{al.rule_description || '—'}</td>
                    <td className="mono">{al.src_ip || '—'}</td>
                    <td className="mono">{al.dst_port ?? '—'}</td>
                    <td className="mono" style={{ fontWeight: 700, color: riskColor(al.risk_score) }}>{al.risk_score ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {toast && <div className={`toast ${toast.type}`}>{toast.msg}</div>}
    </div>
  );
}

function riskColor(score) {
  if (score == null) return 'var(--text-dim)';
  if (score >= 8) return 'var(--high)';
  if (score >= 5) return 'var(--medium)';
  return 'var(--low)';
}
